use std::{fmt::Display, fs, time::Instant};

use anyhow::{Context, Result};
use libbpf_rs::query::ProgInfoIter;
use libbpf_sys::bpf_enable_stats;
use procfs::KernelVersion;

const PROCFS_BPF_STATS_ENABLED: &str = "/proc/sys/kernel/bpf_stats_enabled";

#[derive(Clone, Debug)]
pub struct BpfProgramStats {
    pub id: u32,
    pub bpf_type: String,
    pub name: String,
    pub prev_runtime_ns: u64,
    pub run_time_ns: u64,
    pub prev_run_cnt: u64,
    pub run_cnt: u64,
    pub instant: Instant,
    pub period_ns: u128,
}

impl Display for BpfProgramStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BpfProgram({}, {}, {}, {}, {})",
            self.id, self.bpf_type, self.name, self.run_time_ns, self.run_cnt,
        )
    }
}

pub fn enable_bpf_stats() -> Result<()> {
    let kernel_version = KernelVersion::current()?;
    // let _owned_fd: OwnedFd;
    let stats_syscall_supported = kernel_version.ge(&KernelVersion::new(5, 8, 0));

    // enable BPF stats via syscall if supported
    // otherwise, enable via procfs
    if stats_syscall_supported {
        let fd = unsafe { bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
        if fd < 0 {
            panic!("Failed to enable BPF stats via syscall");
        }
        // _owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    } else {
        fs::write(PROCFS_BPF_STATS_ENABLED, b"1").context(format!(
            "Failed to enable BPF stats via {}",
            PROCFS_BPF_STATS_ENABLED
        ))?;
    }

    Ok(())
}

pub fn get_bpf_stats() -> Vec<BpfProgramStats> {
    let mut progs = Vec::new();
    let iter = ProgInfoIter::default();
    for prog in iter {
        let instant = Instant::now();

        let prog_name = match prog.name.to_str() {
            Ok(name) => name.to_string(),
            Err(_) => continue,
        };
        if prog_name.is_empty() {
            continue;
        }
        let bpf_type = prog.ty.to_string();
        // println!("Program name: {prog_name}\ttype: {bpf_type}");

        let bpf_program = BpfProgramStats {
            id: prog.id,
            bpf_type,
            name: prog_name,
            prev_runtime_ns: 0,
            run_time_ns: prog.run_time_ns,
            prev_run_cnt: 0,
            run_cnt: prog.run_cnt,
            instant,
            period_ns: 0,
        };
        progs.push(bpf_program);
    }
    progs
}
