use std::{
    env,
    ffi::{OsStr, OsString},
    fs, io,
    path::PathBuf,
    process::Command,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use ebql_prototype::{
    bpf_gen::{BpfCompiler, StructRepr},
    bpf_select::BpfSelect,
    bpf_types::{Field, TracepointEvent, Type},
};
use libbpf_rs::*;

// Increase the memlock limit. See https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#locked-memory-limits
fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }
    Ok(())
}

fn main() {
    bump_memlock_rlimit().unwrap();

    let e = TracepointEvent {
        path: "tracepoint/syscalls/sys_enter_pread64".into(),
    };
    let fd = Field {
        _event: Some(e.clone()),
        _off: Some(0),
        _name: "fd".into(),
        _type: Type::U64,
    };
    let count = Field {
        _event: Some(e.clone()),
        _off: Some(2),
        _name: "count".into(),
        _type: Type::U64,
    };
    let time = Field {
        _event: None,
        _off: None,
        _name: "time".into(),
        _type: Type::U64,
    };
    let pid = Field {
        _event: None,
        _off: None,
        _name: "pid".into(),
        _type: Type::S32,
    };

    let select = BpfSelect {
        event: e.clone(),
        fields: vec![fd.clone(), count.clone(), time.clone(), pid.clone()],
    };

    // Generate BPF program from select definition
    let mut handler = BpfCompiler::new(select).compile().unwrap();
    // Load and attach programs
    let _links = handler.load_and_attach();

    // Get ringbuffer
    let rb = handler.get_ring_buffer().unwrap();

    loop {
        rb.poll(Duration::from_millis(1000)).unwrap();
    }
}
