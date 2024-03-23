pub trait Event {
    fn program_type() -> ProgramType;
}

/// BPF program types. Details can be found at https://docs.kernel.org/bpf/libbpf/program_types.html.
/// TODO: support more program types
pub enum ProgramType {
    Tracepoint,
    RawTracepoint,
    Usdt,
    Kprobe,
    Kretprobe,
    Uprobe,
    Uretprobe,
    Iter,
    Xdp,
    Tc,
    Lsm,
}

impl ProgramType {
    /// Returns the ELF section name in libbpf. Follows naming connections specified at https://docs.kernel.org/bpf/libbpf/program_types.html.
    pub fn section_name(&self) -> &str {
        match self {
            // For (raw) tracepoints, both (raw_)tp and (raw_)tracepoint is acceptable.
            ProgramType::Tracepoint => "tp",
            ProgramType::RawTracepoint => "raw_tp",
            ProgramType::Usdt => "usdt",
            ProgramType::Kprobe => "kprobe",
            ProgramType::Kretprobe => "kretprobe",
            ProgramType::Uprobe => "uprobe",
            ProgramType::Uretprobe => "uretprobe",
            ProgramType::Iter => "iter",
            ProgramType::Xdp => "xdp",
            ProgramType::Tc => "tc",
            ProgramType::Lsm => "lsm",
        }
    }
}
