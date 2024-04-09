use std::str::FromStr;

use anyhow::{bail, Result};

/// System variables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemVar {
    PID,
    TGID,
    CPU,
    COMM,
    CGROUP,
}

impl SystemVar {
    pub fn get_helper(&self) -> &str {
        match self {
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
            "pid" => Ok(SystemVar::PID),
            "tgid" => Ok(SystemVar::TGID),
            "cpu" => Ok(SystemVar::CPU),
            "comm" => Ok(SystemVar::COMM),
            "cgroup" => Ok(SystemVar::CGROUP),
            _ => bail!("System var {input} does not exist"),
        }
    }
}
