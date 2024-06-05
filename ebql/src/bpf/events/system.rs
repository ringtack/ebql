use std::{fmt::Display, str::FromStr};

use anyhow::{bail, Result};
use strum::EnumIter;

use crate::bpf::{Field, Type};

const TASK_COMM_LEN: usize = 16;

/// System variables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, EnumIter)]
pub enum SystemVar {
    TIME,
    PID,
    TGID,
    CPU,
    COMM,
    CGROUP,
}

impl SystemVar {
    pub fn to_field(&self) -> Field {
        match self {
            SystemVar::TIME => {
                Field {
                    _name: String::from("time"),
                    _type: Type::U64,
                    _arr: None,
                    _off: None,
                }
            }
            SystemVar::PID => {
                Field {
                    _name: String::from("pid"),
                    _type: Type::U64,
                    _arr: None,
                    _off: None,
                }
            }
            SystemVar::TGID => {
                Field {
                    _name: String::from("tgid"),
                    _type: Type::U64,
                    _arr: None,
                    _off: None,
                }
            }
            SystemVar::CPU => {
                Field {
                    _name: String::from("cpu"),
                    _type: Type::U64,
                    _arr: None,
                    _off: None,
                }
            }
            SystemVar::COMM => {
                Field {
                    _name: String::from("comm"),
                    _type: Type::String(TASK_COMM_LEN),
                    _arr: None,
                    _off: None,
                }
            }
            SystemVar::CGROUP => {
                Field {
                    _name: String::from("cgroup"),
                    _type: Type::U64,
                    _arr: None,
                    _off: None,
                }
            }
        }
    }

    pub fn get_field(sv: &str) -> Result<Field> {
        match sv {
            "time" => Ok(SystemVar::TIME.to_field()),
            "pid" => Ok(SystemVar::PID.to_field()),
            "tgid" => Ok(SystemVar::TGID.to_field()),
            "cpu" => Ok(SystemVar::CPU.to_field()),
            "comm" => Ok(SystemVar::COMM.to_field()),
            "cgroup" => Ok(SystemVar::CGROUP.to_field()),
            _ => bail!("System var {sv} does not exist"),
        }
    }

    pub fn get_helper(&self) -> &str {
        match self {
            SystemVar::TIME => "TIME",
            SystemVar::PID => "PID",
            SystemVar::TGID => "TGID",
            SystemVar::CPU => "CPU",
            SystemVar::COMM => "COMM",
            SystemVar::CGROUP => "CGROUP",
        }
    }
}

impl FromStr for SystemVar {
    type Err = anyhow::Error;

    /// Must be lower case!
    fn from_str(input: &str) -> Result<SystemVar> {
        match input {
            "time" => Ok(SystemVar::TIME),
            "pid" => Ok(SystemVar::PID),
            "tgid" => Ok(SystemVar::TGID),
            "cpu" => Ok(SystemVar::CPU),
            "comm" => Ok(SystemVar::COMM),
            "cgroup" => Ok(SystemVar::CGROUP),
            _ => bail!("System var {input} does not exist"),
        }
    }
}

impl Display for SystemVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemVar::TIME => write!(f, "time"),
            SystemVar::PID => write!(f, "pid"),
            SystemVar::TGID => write!(f, "tgid"),
            SystemVar::CPU => write!(f, "cpu"),
            SystemVar::COMM => write!(f, "comm"),
            SystemVar::CGROUP => write!(f, "cgroup"),
        }
    }
}
