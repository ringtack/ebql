//! Kernel eBPF event interface types.

use std::{rc::Rc, str::FromStr};

use anyhow::Result;

use super::Field;

/// Available program types.
pub mod program_types;

/// Tracepoints representation.
pub mod tracepoints;

/// System information.
pub mod system;

use program_types::*;
use system::*;
use tracepoints::*;

/// Event trait.
pub trait Event {
    /// Gets the event program type.
    fn program_type(&self) -> ProgramType;

    /// Gets the event name.
    fn name(&self) -> String;

    /// Gets the event id.
    fn id(&self) -> u64;

    /// Gets the arguments' representations at the event.
    fn get_args(&self, args: &[&str]) -> Result<Vec<Field>>;

    /// Gets the context name at the event.
    fn ctx(&self) -> String;
}

/// Gets the field associated with an event + name, if it exists.
pub fn get_event_field<S: AsRef<str>>(e: &Box<dyn Event>, field: S) -> Option<Field> {
    let t = e.program_type();
    match t {
        ProgramType::Tracepoint => {
            let te = TracepointEvent::from_str(&e.name()).unwrap();
            let e = TP_ARGS.get(&te);
            match e {
                Some(fields) => {
                    let f = fields.get(field.as_ref());
                    f.cloned()
                }
                None => None,
            }
        }
        ProgramType::RawTracepoint => todo!(),
        ProgramType::Usdt => todo!(),
        ProgramType::Kprobe => todo!(),
        ProgramType::Kretprobe => todo!(),
        ProgramType::Uprobe => todo!(),
        ProgramType::Uretprobe => todo!(),
        ProgramType::Iter => todo!(),
        ProgramType::Xdp => todo!(),
        ProgramType::Tc => todo!(),
        ProgramType::Lsm => todo!(),
    }
}
