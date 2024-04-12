//! Kernel eBPF event interface types.

use std::{str::FromStr, sync::Arc};

use anyhow::Result;

use super::Field;

/// Available program types.
pub mod program_types;

/// Tracepoints representation.
pub mod tracepoints;

/// System information.
pub mod system;

use program_types::*;
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
    fn get_all_args(&self) -> Result<Vec<Field>>;

    /// Gets the argument representation at the event.
    fn get_arg(&self, args: &str) -> Result<Field>;

    /// Gets the arguments' representations at the event.
    fn get_args(&self, args: &[&str]) -> Result<Vec<Field>>;

    /// Gets the context name at the event.
    fn ctx(&self) -> String;
}

/// Gets the event associated with a name.
pub fn get_event<S: AsRef<str>>(event: S) -> Option<Arc<dyn Event>> {
    // Try tracepoints first
    if let Ok(tp) = TracepointEvent::from_str(event.as_ref()) {
        return Some(Arc::new(tp));
    }

    // TODO: implement other event types; will probably need an as_any trait
    // impl to allow additional contexts e.g. from kprobes
    None
}

/// Gets the field associated with an event + name, if it exists.
pub fn get_event_field<S: AsRef<str>>(e: &Arc<dyn Event>, field: S) -> Option<Field> {
    let t = e.program_type();
    match t {
        ProgramType::Tracepoint => {
            let te = TracepointEvent::from_str(&e.name()).unwrap();
            let e = TP_ARGS.get(&te);
            match e {
                Some(fields) => {
                    let f = fields.get(field.as_ref());
                    // TODO: fix this logic later; right now if it's a system call instead of event
                    // field it'll just manually construct the bpf_types::Field elsewhere; it's okay
                    // for now since the program builder looks up for sys calls, but it's pretty
                    // janky and should be fixed i think
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
