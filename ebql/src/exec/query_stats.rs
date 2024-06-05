use super::bpf_stats::BpfProgramStats;

pub struct QueryStats {
    pub us_stats: UserspaceStats,
    pub bpf_stats: BpfProgramStats,
}

impl QueryStats {
    pub fn new(us_stats: UserspaceStats, bpf_stats: BpfProgramStats) -> Self {
        Self {
            us_stats,
            bpf_stats,
        }
    }
}

pub struct UserspaceStats {
    // TODO: implement
}

impl UserspaceStats {
    pub fn new() -> Self {
        Self {}
    }
}
