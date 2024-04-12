//! BPF Program representation.

use std::{collections::HashMap, path::PathBuf, process::Command, thread, time::Duration};

use anyhow::{bail, Context, Result};
use crossbeam::channel::{unbounded, Receiver};
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};

use super::MapDef;
use crate::{prog_builder::BuildResult, program::Program, record_batch::RecordBatch};

/// Handle over a BPF Object (which can itself contain multiple BPF programs).
/// TODO: later, if necessary, expose interface for pinning maps.
pub struct Object {
    /// Path of object file
    pub path: PathBuf,
    /// Collection of programs in this object
    pub progs: HashMap<String, Program>,
    /// Collection of map definitions in the object.
    pub maps: HashMap<String, MapDef>,
    /// Libbpf object of loaded BPF object (with all info across all programs)
    obj: libbpf_rs::Object,
}

impl Object {
    /// Loads a new program from a collection of build results: in particular,
    /// links together multiple object files into one BPF object to facilitate
    /// map sharing. Outputs the result in one <name>.bpf.o.
    pub fn load<S: AsRef<str>>(
        name: S,
        objs: Vec<BuildResult>,
        pins: Option<&HashMap<String, PathBuf>>,
    ) -> Result<Self> {
        if objs.len() == 0 {
            bail!("Must call program with at least one object");
        }
        // Get final object path
        let dir = objs[0].obj_path.parent().unwrap();
        let mut dst_path = PathBuf::from(dir);
        dst_path.push(format!("{}.bpf.o", name.as_ref()));

        // Run bpftool if >1 build results
        if objs.len() > 1 {
            // Link together into one bpf object
            let bpftool = get_bpftool_path()?;
            // Create command arguments
            let args = vec!["gen", "object"]
                .into_iter()
                // Add final target
                .chain(std::iter::once(dst_path.to_str().unwrap()))
                .chain(
                    // Convert objects into their file names
                    objs.iter().map(|br| br.obj_path.to_str().unwrap()),
                )
                .collect::<Vec<_>>();
            // Link into one file
            let mut cmd = Command::new(bpftool);
            let out = cmd.args(args).output().context("failed to call bpftool")?;
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr).to_string();
                bail!("Linking objects failed: {err}");
            }
        }

        // Now, we have one object, so open as BPF object
        let mut open_obj = ObjectBuilder::default().open_file(&dst_path)?;

        // For each pin specification, either re-use pinned map, or set pin path
        if let Some(pins) = pins {
            for (map, pin_path) in pins {
                match open_obj.map_mut(map) {
                    Some(m) => {
                        if let Err(_) = m.reuse_pinned_map(pin_path) {
                            m.set_pin_path(pin_path)?;
                        }
                    }
                    None => bail!("Attempted to pin non-existent map {map}"),
                }
            }
        }

        // Load into system
        let obj = open_obj.load().unwrap();

        // Construct programs for each individual bpf program
        let progs = objs
            .iter()
            .map(|br| {
                // Get program associated with this build result
                (
                    br.name.clone(),
                    Program::new(br.structs.clone(), br.globals.clone(), br.ringbuf.clone()),
                )
            })
            .collect();
        // Consolidate maps across programs
        let maps = objs
            .iter()
            .map(|br| br.maps.clone())
            .reduce(|mut acc_maps, maps| {
                acc_maps.extend(maps);
                acc_maps
            })
            .unwrap();

        Ok(Self {
            obj,
            path: dst_path,
            progs,
            maps,
        })
    }

    /// Attaches all programs to the kernel.
    pub fn attach_progs(&mut self) -> Result<()> {
        let progs = self.progs.keys().cloned().into_iter().collect::<Vec<_>>();
        for prog in progs {
            self.attach_prog(prog)?;
        }
        Ok(())
    }

    /// Attaches program with specified name to the kernel.
    pub fn attach_prog(&mut self, name: String) -> Result<()> {
        let prog = self.obj.prog_mut(&name).unwrap();

        // TODO: add extra metadata somewhere along the line for
        // uprobes/kprobes/perf events, and handle here
        use libbpf_rs::ProgramType::*;
        let link = match prog.prog_type() {
            Tracepoint | RawTracepoint => prog.attach()?,
            _ => unimplemented!("logic for other events"),
        };

        // Get program handle for this program
        let prog = self.progs.get_mut(&name).unwrap();
        // After attaching, build channel and ring buffer handler
        let (tx, rx) = unbounded();
        let mut rb = RingBufferBuilder::new();
        let rb_repr = prog.ring_buffer.clone();
        rb.add(
            // TODO: migrate this into RingBuf struct
            self.obj.map(&prog.ring_buffer.name).unwrap(),
            move |buf: &[u8]| -> i32 {
                // Error if buffer is not some multiple of struct size
                if buf.len() % rb_repr.s_repr.sz != 0 {
                    log::error!(
                        "Received buffer of size {} (does not divide struct size {})",
                        buf.len(),
                        rb_repr.s_repr.sz
                    );
                    return 0;
                }

                // Iterate over each byte chunk, converting into a record
                let records = buf
                    .chunks(rb_repr.s_repr.sz)
                    .into_iter()
                    .map(|buf| rb_repr.s_repr.produce_record(buf))
                    .collect::<Result<Vec<_>>>();
                if !records.is_ok() {
                    log::error!(
                        "Failed to parse bytes into record batch of struct {}",
                        rb_repr.s_repr.name
                    );
                    return 0;
                }

                let rb = RecordBatch::new(rb_repr.s_repr.schema.clone(), records.unwrap());

                if let Err(err) = tx.send(rb) {
                    log::warn!("Failed to send to program {}'s channel: {}", name, err);
                }
                return 0;
            },
        )?;
        let rb = rb.build()?;
        // Indefinitely poll ringbuffer
        thread::spawn({
            let rb = rb;
            move || while rb.poll(Duration::MAX).is_ok() {}
        });

        // Add to program info
        prog.add_attach_info(link, rx);
        Ok(())
    }

    /// Gets the receiving channel for events for the program. Returns None if
    /// attach_prog is not called beforehand.
    pub fn prog_rx<S: AsRef<str>>(&self, name: S) -> Option<Receiver<RecordBatch>> {
        self.progs.get(name.as_ref()).unwrap().out_rx.clone()
    }

    // TODO: find out how to set global variables
}

fn get_bpftool_path() -> Result<PathBuf> {
    // TODO: find how to automatically build submodule
    // let root = get_project_root()?;
    // root.join(PathBuf::from("bpftool_build/bpftool"))
    which::which("bpftool").with_context(|| format!("failed to find bpftool"))
}
