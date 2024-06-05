//! Program builder for eBPF code.

use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    fs::{OpenOptions},
    io::{self, Write},
    marker::PhantomData,
    path::{PathBuf},
    process::Command,
    str::FromStr,
};

use anyhow::{bail, Context, Result};

use super::{Field, MapDef, Struct};
use crate::{
    events::system::SystemVar,
    map::{MapType, RingBuf},
};

// Common characters
const NL: u8 = '\n' as u8;
const NLNL: [u8; 2] = [NL; 2];
const TAB: u8 = '\t' as u8;

// Common variable modifications
pub const CONST: &str = "const";
pub const VOLATILE: &str = "volatile";
pub const STATIC: &str = "static";
pub const ALWAYS_INLINE: &str = "__always_inline";

// Common map attributes
pub const __UINT: &str = "__uint";
pub const __TYPE: &str = "__type";

// Map types
pub const RINGBUF: &str = "BPF_MAP_TYPE_RINGBUF";
pub const HASHMAP: &str = "BPF_MAP_TYPE_HASH";

// Map attribute keys
pub const TYPE: &str = "type";
pub const MAX_ENTRIES: &str = "max_entries";

// Default license for most BPF programs
const DEFAULT_LICENSE: &str = r#"char LICENSE[] SEC("license") = "Dual BSD/GPL";"#;

/// To re-use field features, we brand them as expressions; while expressions
/// exist separately and not every field in the Field struct is relevant, this
/// gives us a convenient way to represent what we need (i.e. <type-name> pair).
pub type Expr = Field;

/// Stores metadata resulting from a program build.
pub struct BuildResult {
    pub obj_path: PathBuf,
    pub name: String,
    pub structs: HashMap<String, Struct>,
    pub maps: HashMap<String, MapDef>,
    pub globals: HashMap<String, Expr>,
    pub ringbuf: RingBuf,
}

impl BuildResult {
    pub fn new(
        obj_path: PathBuf,
        name: String,
        structs: HashMap<String, Struct>,
        maps: HashMap<String, MapDef>,
        globals: HashMap<String, Expr>,
        ringbuf: RingBuf,
    ) -> Self {
        Self {
            obj_path,
            name,
            structs,
            maps,
            globals,
            ringbuf,
        }
    }
}

/// Code builder for BPF programs.
pub struct BpfCodeBuilder<S = Base> {
    /// Output file name (without extensions; this will add the
    /// `.bpf.c`/`.bpf.h` automatically)
    name: String,
    /// Section in which this program belongs to
    section: String,

    /// Buffers for header file (name.bpf.h). The only included file will be
    /// `common.bpf.h`, which should have all relevant definitions from
    /// libbpf/bpf itself.
    ///
    /// Macro definitions
    macros_buf: Vec<u8>,
    /// Struct definitions
    structs_buf: Vec<u8>,
    /// Global variable definitions (i.e. filters, flags, etc.)
    globals_buf: Vec<u8>,

    /// Buffers for source file (name.bpf.c).
    ///
    /// Includes definitions for the source file (e.g. to add aggregation
    /// headers on top of own header)
    includes_buf: Vec<u8>,
    /// Code construction of the actual program function(s).
    code_buf: Vec<u8>,
    /// Map definitions (i.e. output ringbuf!)
    maps_buf: Vec<u8>,

    /// Buffers for external includes files: {tmp_path -> include contents}
    ext_includes: HashMap<String, String>,

    /// Store data for creating program handle
    ///
    /// Store globals defined (name -> field definition)
    globals: HashMap<String, Expr>,
    /// Store structs created (name -> struct definition)
    // TODO: expand if necessary
    structs: HashMap<String, Struct>,
    /// Store output ringbuf representation
    ring_buffer: Option<RingBuf>,
    /// Store maps defined (name -> map definition)
    /// TODO: migrate to processing generated libbpf obj
    maps: HashMap<String, MapDef>,

    /// Current prefix while code construction
    prefix: Vec<u8>,
    /// type marker to ensure type safety when constructing things
    _marker: PhantomData<S>,
}

impl BpfCodeBuilder<Base> {
    pub fn new(name: String, section: String) -> Self {
        let mut cb = Self {
            name: name.clone(),
            section,
            macros_buf: Vec::new(),
            structs_buf: Vec::new(),
            maps_buf: Vec::new(),
            globals_buf: Vec::new(),

            includes_buf: Vec::new(),
            code_buf: Vec::new(),

            maps: HashMap::new(),
            structs: HashMap::new(),
            ring_buffer: None,

            ext_includes: HashMap::new(),

            prefix: Vec::new(),
            _marker: PhantomData,
            globals: HashMap::new(),
        };

        // Pre-initialization: always include own header, "{name}.bpf.h"
        let hdr = format!("{}.bpf.h", &name);
        cb.write_includes(&hdr, false, Some(&format!("{name}'s definitions")));

        cb
    }

    /// Adds an external includes file to the program by creating a temporary
    /// includes file from the provided include file, then adding it to the
    /// program's include list.
    pub fn add_external_includes<S: AsRef<str>>(&mut self, name: S, includes: String) -> &mut Self {
        // Create header name from include name and program name
        let hdr_name = format!("{}_{}.bpf.h", name.as_ref(), self.name);

        // Insert header into external includes
        self.ext_includes.insert(hdr_name.clone(), includes);

        // Write includes to buffer
        let comment = format!("External includes ({})", name.as_ref());
        self.write_includes(&hdr_name, false, Some(&comment));
        self
    }

    /// Writes a struct to the program header definition.
    pub fn write_struct(self, s: &Struct) -> Self {
        let mut cb = self.start_struct();
        for field in &s.fields {
            cb.write_field(field);
        }
        let mut cb = cb.close(&s.name);
        cb.structs.insert(s.name.clone(), s.clone());
        cb
    }

    /// Writes a map to the program header definition.
    pub fn write_map(self, map_def: &MapDef) -> Self {
        let mut cb = self.start_map();
        let map_type = map_def.map_type.to_string();
        let key_type = map_def.key_type.to_string();
        let max_entries = map_def.max_entries.to_string();
        cb.write_attr(__UINT, "type", &map_type);
        cb.write_attr(__TYPE, "key", &key_type);
        cb.write_attr(__UINT, "value", &map_def.value_type);
        cb.write_attr(__UINT, "max_entries", &max_entries);
        if map_def.flags.val > 0 {
            let flags = map_def.flags.val.to_string();
            cb.write_attr(__UINT, "map_flags", &flags);
        }
        if let Some(path) = &map_def.pin {
            cb.write_attr(__UINT, "pinning", path.to_str().unwrap());
        }
        let mut cb = cb.close(&map_def.name);
        cb.maps.insert(map_def.name.clone(), map_def.clone());
        cb
    }

    /// Writes an output ring buffer to the program source definition.
    pub fn write_ring_buffer(self, rb_def: &RingBuf) -> Self {
        let mut cb = self.start_map();
        let map_type = MapType::RingBuffer.to_string();
        let max_entries = (rb_def.max_entries * rb_def.s_repr.sz as u64).to_string();
        cb.write_attr(__UINT, "type", &map_type);
        cb.write_attr(__UINT, "max_entries", &max_entries);
        let cb = cb.close(&rb_def.name);
        // Write output schema in ring buf to header definition
        let mut cb = cb.write_struct(&rb_def.s_repr);
        cb.ring_buffer = Some(rb_def.clone());

        cb
    }

    /// Adds an includes header directive. Specify whether the header file is a
    /// system or project file. Optionally add a comment on inclusion
    pub fn write_includes(
        &mut self,
        header: &str,
        system: bool,
        comment: Option<&str>,
    ) -> &mut Self {
        let (open, close) = if system { ('<', '>') } else { ('"', '"') };
        let str = format!(
            "#include {}{}{} /* {} */",
            open,
            header,
            close,
            comment.unwrap_or_default()
        );
        self.includes_buf.extend(str.as_bytes());
        self.includes_buf.push(NL);
        self
    }

    /// Adds a macro definition. Automatically escapes the macro by enclosing it
    /// in parentheses.
    pub fn write_macro<S1: AsRef<str>, S2: AsRef<str>>(&mut self, name: S1, val: S2) -> &mut Self {
        let str = format!("#define {} ({})", name.as_ref(), val.as_ref());
        self.macros_buf.extend(str.as_bytes());
        self.includes_buf.push(NL);
        self
    }

    /// Writes a global expression.
    pub fn write_global<S: AsRef<str>>(
        &mut self,
        mods: Vec<&str>,
        expr: &Expr,
        value: Option<S>,
    ) -> &mut Self {
        let mods = mods.join(" ");
        let assignment = match value {
            Some(s) => format!(" = {}", s.as_ref()),
            None => String::new(),
        };
        let str = format!("{} {}{};", mods, expr, assignment);
        self.globals_buf.extend(str.as_bytes());
        self.globals_buf.push(NL);
        self
    }

    /// Starts a struct definition. The user must close the struct definition
    /// using self.close().
    pub fn start_struct(mut self) -> BpfCodeBuilder<StructConstruction> {
        self.structs_buf.extend("typedef struct {".as_bytes());
        self.structs_buf.push(NL);

        // Convert into different type
        self.prefix.push(TAB);
        BpfCodeBuilder::<StructConstruction> {
            _marker: PhantomData,
            ..self.into()
        }
    }

    /// Starts a map definition. The user must close the map definition using
    /// self.close().
    pub fn start_map(mut self) -> BpfCodeBuilder<MapConstruction> {
        let bytes = "struct {".as_bytes();
        self.maps_buf.extend(bytes);
        self.maps_buf.push(NL);

        // Convert into different type
        self.prefix.push(TAB);
        BpfCodeBuilder::<MapConstruction> {
            _marker: PhantomData,
            ..self.into()
        }
    }

    /// Starts a BPF program function definition. The user must close the
    /// function definition using self.close().
    pub fn start_function(mut self, args: &[Expr]) -> BpfCodeBuilder<BodyConstruction> {
        // Construct function header
        let mut str = format!(r#"SEC("{}")"#, self.section);
        str.push(NL as char);
        str.push_str(&format!("u32 {}(", self.name));
        for (i, arg) in args.iter().enumerate() {
            str.push_str(&format!("{}", arg));
            if i != args.len() - 1 {
                str.push(',');
            }
        }
        str.push_str(") {");
        let bytes = str.as_bytes();

        // Add to buffer
        self.code_buf.extend(bytes);
        self.code_buf.push(NL);

        // Convert into different type
        self.prefix.push(TAB);
        BpfCodeBuilder::<BodyConstruction> {
            _marker: PhantomData,
            ..self.into()
        }
    }

    /// Builds the program, returning the path to the output object file.
    pub fn build(self, out_dir: &PathBuf) -> Result<BuildResult> {
        // Build program header
        let hdr_len = self.structs_buf.len() + self.macros_buf.len() + self.globals_buf.len();
        let mut hdr_buf = Vec::with_capacity(hdr_len);

        hdr_buf.extend("#pragma once".as_bytes());
        hdr_buf.push(NL);
        hdr_buf.extend(format!("// *** HEADER FOR QUERY {} *** //", self.name).into_bytes());
        // Always include common.bpf.h in includes header
        hdr_buf.push(NL);
        hdr_buf.extend(r#"#include "common.bpf.h" /* common definitions */"#.as_bytes());
        hdr_buf.push(NL);
        hdr_buf.push(NL);

        hdr_buf.extend("// *** MACRO DEFINITIONS *** //".as_bytes());
        hdr_buf.push(NL);
        hdr_buf.extend(self.macros_buf);
        hdr_buf.push(NL);
        hdr_buf.push(NL);

        hdr_buf.extend("// *** STRUCT DEFINITIONS *** //".as_bytes());
        hdr_buf.push(NL);
        hdr_buf.extend(self.structs_buf);
        hdr_buf.push(NL);
        hdr_buf.push(NL);

        hdr_buf.extend("// *** GLOBAL DEFINITIONS *** //".as_bytes());
        hdr_buf.push(NL);
        hdr_buf.extend(self.globals_buf);
        hdr_buf.push(NL);
        hdr_buf.push(NL);

        let hdr_name = format!("{}.bpf.h", &self.name);
        let hdr_path = out_dir.join(hdr_name);
        // Write to output file
        let mut file = OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(&hdr_path)?;
        file.write_all(&hdr_buf)?;

        // Write all external header files
        for (ext_hdr_name, ext_hdr_text) in &self.ext_includes {
            let ext_hdr_path = out_dir.join(ext_hdr_name);
            // Write to output file
            let mut file = OpenOptions::new()
                .truncate(true)
                .write(true)
                .create(true)
                .open(&ext_hdr_path)?;
            file.write_all(ext_hdr_text.as_bytes())?;
        }

        // Build program source
        let cap = self.includes_buf.len() + self.maps_buf.len() + self.code_buf.len();
        let mut src_buf = Vec::with_capacity(cap);

        src_buf.extend(format!("// *** SOURCE FOR {} *** //", self.name).into_bytes());
        src_buf.push(NL);
        src_buf.push(NL);

        src_buf.extend("// *** INCLUDES SECTION *** //".as_bytes());
        src_buf.push(NL);
        src_buf.extend(self.includes_buf);
        src_buf.extend(NLNL);

        src_buf.extend("// *** MAPS SECTION *** //".as_bytes());
        src_buf.push(NL);
        src_buf.extend(self.maps_buf);
        src_buf.extend(NLNL);

        src_buf.extend("// *** CODE SECTION *** //".as_bytes());
        src_buf.push(NL);
        src_buf.extend(self.code_buf);
        src_buf.extend(NLNL);

        src_buf.extend("// *** LICENSE *** //".as_bytes());
        src_buf.push(NL);
        src_buf.extend(DEFAULT_LICENSE.as_bytes());
        src_buf.push(NL);

        let src_name = format!("{}.bpf.c", &self.name);
        let src_path = out_dir.join(src_name);
        // Write to output file
        let mut file = OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(&src_path)?;
        file.write_all(&src_buf)?;

        // Compile program down to object file
        let root = get_project_root().unwrap();
        let dst_path = src_path.clone().with_extension("o");
        let vmlinux_dir = root.join("bpf/");
        let mut cmd = Command::new(OsStr::new("clang"));
        // Code yoinked from libbpf-cargo's compilation flags
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

        Ok(BuildResult::new(
            dst_path,
            self.name,
            self.structs,
            self.maps,
            self.globals,
            self.ring_buffer.unwrap(),
        ))
    }
}

impl BpfCodeBuilder<StructConstruction> {
    pub fn write_field(&mut self, f: &Expr) -> &mut Self {
        self.structs_buf.extend(&self.prefix);
        let str = format!("{};", f);
        self.structs_buf.extend(str.as_bytes());
        self.structs_buf.push(NL);

        self
    }

    pub fn close<S: AsRef<str>>(mut self, name: S) -> BpfCodeBuilder<Base> {
        self.structs_buf
            .extend(format!("}} {};", name.as_ref()).as_bytes());
        self.structs_buf.push(NL);

        self.prefix.pop();
        BpfCodeBuilder::<Base> {
            _marker: PhantomData,
            ..self.into()
        }
    }
}

impl BpfCodeBuilder<MapConstruction> {
    pub fn write_attr(&mut self, attr: &str, key: &str, val: &str) -> &mut Self {
        let str = format!("{}({}, {});", attr, key, val);
        self.maps_buf.extend(&self.prefix);
        self.maps_buf.extend(str.as_bytes());
        self.maps_buf.push(NL);

        self
    }

    pub fn close(mut self, name: &str) -> BpfCodeBuilder<Base> {
        let str = format!(r#"}} {} SEC(".maps");"#, name);
        self.maps_buf.extend(str.as_bytes());
        self.maps_buf.push(NL);

        self.prefix.pop();
        BpfCodeBuilder::<Base> {
            _marker: PhantomData,
            ..self.into()
        }
    }
}

impl BpfCodeBuilder<BodyConstruction> {
    /// Declares a field, and writes the result into the struct.
    pub fn write_field(&mut self, f: &Field, st: Option<(&str, bool)>) -> &mut Self {
        let str = match st {
            Some((st, ptr)) => format!("{}{}{}", st, if ptr { "->" } else { "." }, f._name),
            None => {
                // First declare it, then get its identifier
                self.write_var_declaration(f);
                f._name.clone()
            }
        };
        // If str doesn't have an event, use a generic kernel system call
        // TODO: find way to encode whether or not field has an event, rather than
        // relying on no name conflicts
        let sv = SystemVar::from_str(&f._name);
        match sv {
            Ok(sv) => {
                let func = sv.get_helper();
                let args = vec![str.as_str()];
                self.write_func_call(func, &args);
            }
            Err(_) => {
                let access = match (&f._arr, &f._off) {
                    (Some(arr), Some(off)) => format!("ctx->{arr}[{off}]"),
                    _ => format!("ctx->{}", f._name),
                };
                self.write_var_assignment(&f._name, &access);
            }
        }
        self
    }

    /// Declares a variable without initializing it.
    pub fn write_var_declaration(&mut self, e: &Expr) -> &mut Self {
        let str = format!("{e};");
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    /// Declares and initializes a variable.
    pub fn write_var_initialization(&mut self, e: &Expr, expr_value: &str) -> &mut Self {
        let str = format!("{e} = {expr_value};");
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    /// Assigns to a variable.
    pub fn write_var_assignment(&mut self, expr_name: &str, expr_value: &str) -> &mut Self {
        let str = format!("{} = {};", expr_name, expr_value);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    /// Helper to assign strings.
    pub fn write_str_assignment(&mut self, src: &str, dst: &str, sz: &str) {
        let args = vec![dst, &sz, src];
        self.write_func_call("bpf_probe_read_kernel", &args);
    }

    /// Makes a function call with the provided arguments.
    pub fn write_func_call(&mut self, func: &str, args: &[&str]) -> &mut Self {
        let mut str = format!("{}(", func);
        for (i, arg) in args.iter().enumerate() {
            str.push_str(&format!("{}", arg));
            if i != args.len() - 1 {
                str.push_str(", ");
            }
        }
        str = str + ");";
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    pub fn write_if(&mut self, cond: &str) -> &mut Self {
        let str = format!("if ({}) {{", cond);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);

        self.prefix.push(TAB);
        self
    }

    pub fn write_elif(&mut self, cond: &str) -> &mut Self {
        self.prefix.pop();
        let str = format!("}} else if ({}) {{", cond);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());

        self.prefix.push(TAB);
        self
    }

    pub fn write_else(&mut self) -> &mut Self {
        self.prefix.pop();
        let str = format!("}} else {{");
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());

        self.prefix.push(TAB);
        self
    }

    pub fn close_if(&mut self) -> &mut Self {
        self.prefix.pop();

        self.code_buf.extend(&self.prefix);
        self.code_buf.push('}' as u8);
        self.code_buf.push(NL);
        self
    }

    pub fn write_return(&mut self, val: &str) -> &mut Self {
        let str = format!("return {};", val);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    pub fn close(mut self) -> BpfCodeBuilder<Base> {
        self.code_buf.push('}' as u8);
        self.code_buf.push(NL);
        self.prefix.pop();
        BpfCodeBuilder::<Base> {
            _marker: PhantomData,
            ..self.into()
        }
    }
}

pub(crate) fn get_project_root() -> io::Result<PathBuf> {
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

// State transitions
#[derive(Clone, Copy, Debug, Default)]
pub struct Base;
#[derive(Clone, Copy, Debug)]
pub struct StructConstruction;
#[derive(Clone, Copy, Debug)]
pub struct MapConstruction;
#[derive(Clone, Copy, Debug)]
pub struct BodyConstruction;

#[derive(Clone, Debug)]
pub struct Includes {
    pub file: String,
    pub is_system: bool,
    pub comment: Option<String>,
}
