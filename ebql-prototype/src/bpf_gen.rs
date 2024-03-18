use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    process::Command,
};

use anyhow::{bail, Context, Result};
use rand::distributions::{Alphanumeric, DistString};

use crate::{
    bpf_select::*,
    bpf_types::{Field, Type},
    code_builder::{BpfCodeBuilder, Includes, *},
};

pub struct BpfCompiler {
    // TODO: generalize into more BpfOps
    pub op: BpfSelect,
}

impl BpfCompiler {
    pub fn new(op: BpfSelect) -> BpfCompiler {
        BpfCompiler { op }
    }

    pub fn compile(&self) -> Result<SelectProgramHandler> {
        // Useful includes strings TODO: figure out how to const-ify this...
        let INCLUDES_VEC: [Includes; 4] = [
            Includes {
                file: String::from("vmlinux.h"),
                is_system: false,
                comment: Some("all kernel types".into()),
            },
            Includes {
                file: "bpf/bpf_core_read.h".into(),
                is_system: true,
                comment: Some("for BPF CO-RE helpers".into()),
            },
            Includes {
                file: "bpf/bpf_helpers.h".into(),
                is_system: true,
                comment: Some("most used_helpers: SEC, __always_inline, etc".into()),
            },
            Includes {
                file: "bpf/bpf_tracing.h".into(),
                is_system: true,
                comment: None,
            },
        ];
        let mut cb = BpfCodeBuilder::new();

        // Add basic includes texts
        for inc in &INCLUDES_VEC {
            cb.write_includes(&inc.file, inc.is_system, inc.comment.as_deref());
        }

        // Create struct definition(s) to emit via the ringbuf
        let s_repr = StructRepr::generate_struct(&self.op.fields)?;
        // Write the struct
        let mut cb = cb.write_struct(&s_repr.name);
        for field in &s_repr.fields {
            cb.write_field(&field._name, &field._type.to_string());
        }
        let cb = cb.close();

        // Create ring buf to emit
        let rb = RingBufferRepr::new();
        let mut cb = cb.write_map();
        cb.write_attr(__UINT, TYPE, RINGBUF)
            .write_attr(__UINT, MAX_ENTRIES, "256 * 1024");
        let cb = cb.close(&rb.name);

        // Start definition of BPF program
        let func_name = format!(
            "bpf_select_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 5)
        );
        let ctx = Arg {
            _name: "ctx".into(),
            _type: "struct trace_event_raw_sys_enter *".into(),
        };
        let mut cb = cb.write_function(
            &self.op.event.section_name(),
            &Type::U32.to_string(),
            &func_name,
            &vec![ctx.clone()],
        );

        // Debug
        cb.write_func_call("bpf_printk", &vec!["\"got event\\n\""]);

        let rb_reserve = format!(
            "bpf_ringbuf_reserve(&{}, sizeof({}), 0)",
            &rb.name, &s_repr.name
        );
        let expr = "e";
        cb.write_var_initialization(expr, &format!("{} *", s_repr.name), &rb_reserve);

        // Add null check for e
        cb.write_if(&format!("!{}", expr))
            .write_func_call("bpf_printk", &vec![r#""failed to allocate values\n""#])
            .write_return("1")
            .close_if();

        // Initialize struct values
        for field in &self.op.fields {
            // Get assignment value
            let val = match field._event {
                Some(_) => {
                    // If event provided, should have offset
                    // TODO: ^ is only true for syscalls, will need to change later
                    let off = field._off.unwrap();
                    // Cast to correct type
                    format!("({}) {}->args[{}]", field._type, &ctx._name, off)
                }
                None => {
                    // Hardcoded helpers; eventually should convert into a comprehensive collection
                    match field._name.as_str() {
                        "pid" => "bpf_get_current_pid_tgid() >> 32".into(),
                        "time" => "bpf_ktime_get_ns()".into(),
                        "exec_path" => {
                            unimplemented!()
                        }
                        _ => {
                            unimplemented!()
                        }
                    }
                }
            };
            let expr = format!("{}->{}", expr, field._name);

            // Assign value
            cb.write_var_assignment(&expr, &val);
        }
        // Emit to program rb, and close program
        cb.write_func_call("bpf_ringbuf_submit", &vec![expr, "0"]);
        cb.write_return("0");

        let cb = cb.close();
        let code = cb.build();

        // Get output location
        let root = get_project_root().unwrap();
        let out_dir = get_out_dir(&root).unwrap();
        // Clear directory TODO: change this later
        let _ = fs::remove_dir_all(&out_dir);
        create_dir_if_not_exists(&out_dir).unwrap();
        let filename = format!("{}.bpf.c", func_name);
        let src_path = out_dir.join(filename);

        // Write to output file
        let mut file = OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(&src_path)?;
        file.write_all(code.as_bytes())?;

        // Compile down to object file
        let dst_path = src_path.clone().with_extension("o");
        let vmlinux_dir = root.join("bpf/");
        let mut cmd = Command::new(OsStr::new("clang"));
        cmd.arg(format!("-I{}", vmlinux_dir.display()))
            .arg("-D__TARGET_ARCH_x86_64")
            // Explicitly disable stack protector logic, which doesn't work with
            // BPF. See https://lkml.org/lkml/2020/2/21/1000.
            .arg("-fno-stack-protector")
            .arg("-g")
            .arg("-O2")
            .arg("-target")
            .arg("bpf")
            .arg("-c")
            .arg(src_path)
            .arg("-o")
            .arg(dst_path.clone());

        let output = cmd.output().context("Failed to execute clang")?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            bail!("Compile failed: {err}");
        }

        let handler = SelectProgramHandler::new(PathBuf::from(dst_path), rb, s_repr);
        Ok(handler)
    }
}

// TODO: expand
#[derive(Debug)]
pub struct RingBufferRepr {
    pub name: String,
}

impl RingBufferRepr {
    fn new() -> Self {
        let name = format!(
            "ring_buf_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 5)
        );
        Self { name }
    }
}

#[derive(Debug, Clone)]
pub struct StructRepr {
    // fields used in the struct, in order
    pub fields: Vec<Field>,
    // struct name
    pub name: String,
}

impl StructRepr {
    // Get total size of struct
    pub fn total_size(&self) -> usize {
        self.fields.iter().map(|f| f._type.size()).sum()
    }

    // Extracts the desired field from a provided byte buffer using this struct
    // representation. Assumes the buffer actually has data; otherwise, returns an
    // error.
    pub fn get_field<T>(&self, buf: &[u8], field: &str) -> Result<T> {
        todo!("figure out how to implement dynamic return types")
    }

    // Generates a struct representation, given an operation and its desired fields
    fn generate_struct(fields: &[Field]) -> Result<StructRepr> {
        let name = format!(
            "struct select_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 5)
        );
        // code.push()

        let res = StructRepr {
            fields: fields.to_vec(),
            name,
        };
        Ok(res)
    }
}

fn get_project_root() -> io::Result<PathBuf> {
    let path = env::current_dir()?;
    let mut path_ancestors = path.as_path().ancestors();

    while let Some(p) = path_ancestors.next() {
        let has_cargo = std::fs::read_dir(p)?
            .into_iter()
            .any(|p| p.unwrap().file_name() == OsString::from("Cargo.lock"));
        if has_cargo {
            return Ok(PathBuf::from(p));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Ran out of places to find Cargo.toml",
    ))
}

fn get_out_dir(base: &PathBuf) -> Option<PathBuf> {
    // First we get the arguments for the rustc invocation
    let mut args = std::env::args();

    // Then we loop through them all, and find the value of "out-dir"
    while let Some(arg) = args.next() {
        println!("arg: {arg}");
        if arg.contains("target") {
            let mut path = base.clone();
            path.push(PathBuf::from(arg));
            path.pop();
            path.push("tmp_build");
            return Some(path);
        }
    }
    None
}

// Creates directory if not exists
fn create_dir_if_not_exists(dir: &PathBuf) -> io::Result<()> {
    if let Ok(metadata) = fs::metadata(dir) {
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Directory {} already exists, but is not a directory",
                    dir.display()
                ),
            ));
        }
        Ok(())
    } else {
        fs::create_dir(dir)
    }
}
