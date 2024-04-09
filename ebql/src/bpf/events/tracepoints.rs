//! Tracepoint event representation.

use std::{collections::HashMap, fmt::Display, str::FromStr};

use anyhow::{anyhow, bail, Result};
use lazy_static::lazy_static;

use super::{
    super::{Field, Type},
    Event, ProgramType,
};

/// Tracepoint representation.
impl TracepointEvent {
    fn tp_name(&self) -> String {
        match self {
            TracepointEvent::MmFilemapAddToPageCache => "mm_filemap_add_to_page_cache",
            TracepointEvent::MmFilemapDeleteFromPageCache => "mm_filemap_delete_frompage_cache",
            TracepointEvent::SysEnterPread64 => "sys_enter_pread64",
            TracepointEvent::SysExitPread64 => "sys_exit_pread64",
        }
        .into()
    }

    fn tp_dir(&self) -> String {
        match self {
            TracepointEvent::MmFilemapAddToPageCache => "filemap",
            TracepointEvent::MmFilemapDeleteFromPageCache => "filemap",
            TracepointEvent::SysEnterPread64 => "syscalls",
            TracepointEvent::SysExitPread64 => "syscalls",
        }
        .into()
    }
}

impl Event for TracepointEvent {
    fn program_type(&self) -> ProgramType {
        ProgramType::Tracepoint
    }

    fn name(&self) -> String {
        format!("{}/{}", self.tp_dir(), self.tp_name())
    }

    fn id(&self) -> u64 {
        match self {
            TracepointEvent::MmFilemapAddToPageCache => 498,
            TracepointEvent::MmFilemapDeleteFromPageCache => 499,
            TracepointEvent::SysEnterPread64 => 697,
            TracepointEvent::SysExitPread64 => 696,
        }
    }

    fn get_args(&self, args: &[&str]) -> Result<Vec<Field>> {
        let tp_args = TP_ARGS.get(self);
        match tp_args {
            Some(tp_args) => {
                let mut res = Vec::with_capacity(args.len());
                for arg in args {
                    let f = tp_args.get(*arg);
                    match f {
                        Some(f) => res.push(f.clone()),
                        None => {
                            return Err(anyhow!(format!(
                                "Arg {} not found in tracepoint {}",
                                *arg, self
                            )));
                        }
                    }
                }
                Ok(res)
            }
            None => {
                Err(anyhow!(format!(
                    "Tracepoint {self} should exist in TP_ARGS hashmap",
                )))
            }
        }
    }

    fn ctx(&self) -> String {
        if self.tp_dir().contains("syscall") {
            "struct trace_event_raw_sys_enter".into()
        } else {
            format!("struct trace_event_raw_{}", self.tp_name())
        }
    }
}

/// Enum encoding tracepoint information; parsed by
/// tracepoint_event_generator.rs TODO: implement parser
#[derive(Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum TracepointEvent {
    /// TODO: hard code values for now
    MmFilemapAddToPageCache,
    MmFilemapDeleteFromPageCache,
    SysEnterPread64,
    SysExitPread64,
}

impl Display for TracepointEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for TracepointEvent {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<TracepointEvent> {
        use TracepointEvent::*;
        Ok(match s {
            "filemap/mm_filemap_add_to_page_cache" => MmFilemapAddToPageCache,
            "filemap/mm_filemap_delete_frompage_cache" => MmFilemapDeleteFromPageCache,
            "syscalls/sys_enter_pread64" => SysEnterPread64,
            "syscalls/sys_exit_pread64" => SysExitPread64,
            _ => bail!("Tracepoint event {s} not found"),
        })
    }
}

lazy_static! {
    pub static ref TP_ARGS: HashMap<TracepointEvent, HashMap<String, Field>> = {
        let mut m = HashMap::<TracepointEvent, HashMap<String, Field>>::new();

        // Insert filemap stuff
        m.insert(
            TracepointEvent::MmFilemapAddToPageCache,
            HashMap::from([
                ("pfn".into(), Field::new(
                    "pfn".into(),
                    Type::U64,
                    // true,
                )),
                ("i_ino".into(), Field::new(
                    "i_ino".into(),
                    Type::U64,
                    // true,
                )),
                ("index".into(), Field::new(
                    "index".into(),
                    Type::U64,
                    // true,
                )),
                ("s_dev".into(), Field::new(
                    "s_dev".into(),
                    Type::U32,
                    // true,
                )),
            ]),
        );
        m.insert(
            TracepointEvent::MmFilemapDeleteFromPageCache,
            HashMap::from([
                ("pfn".into(), Field::new(
                    "pfn".into(),
                    Type::U64,
                    // true,
                )),
                ("i_ino".into(), Field::new(
                    "i_ino".into(),
                    Type::U64,
                    // true,
                )),
                ("index".into(), Field::new(
                    "index".into(),
                    Type::U64,
                    // true,
                )),
                ("s_dev".into(), Field::new(
                    "s_dev".into(),
                    Type::U32,
                    // true,
                )),
            ]),
        );

        // Insert pread64 stuff
        m.insert(
            TracepointEvent::SysEnterPread64,
            HashMap::from([
                ("fd".into(), Field::new_with_off(
                    "fd".into(),
                    Type::U64,
                    // true,
                    "args".into(),
                    0,
                )),
                ("buf".into(), Field::new_with_off(
                    "buf".into(),
                    Type::Pointer(Box::new(Type::UChar)),
                    // true,
                    "args".into(),
                    1,
                )),
                ("count".into(), Field::new_with_off(
                    "count".into(),
                    Type::U64,
                    // true,
                    "args".into(),
                    2,
                )),
                ("pos".into(), Field::new_with_off(
                    "pos".into(),
                    Type::U64,
                    // true,
                    "args".into(),
                    3,
                )),
            ]),
        );
        m.insert(
            TracepointEvent::SysExitPread64,
            HashMap::from([
                ("ret".into(), Field::new_with_off(
                    "ret".into(),
                    Type::U64,
                    // true,
                    "args".into(),
                    0,
                )),
            ]),
        );
        m
    };
}
