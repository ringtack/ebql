use std::path::PathBuf;

use serde::Serialize;

use super::{HeaderTemplate, BPF_HEADERS_DIR};

/// Value to scale quantile computations by
const FP_SCALE: usize = 1e6 as usize;

/// BPF Histogram implementation.
#[derive(Serialize)]
pub struct BpfHistogramTemplate {
    n_buckets: usize,
    buckets: String,
    is_log: bool,
    fp_scale: usize,
}

impl BpfHistogramTemplate {
    /// Gets a histogram template from
    pub fn get_tmpl(buckets: &[(usize, usize)]) -> HeaderTemplate<BpfHistogramTemplate> {
        // Check if buckets are log buckets
        let mut is_log = true;
        for (lb, ub) in buckets {
            if *lb != 0 && (ub / lb) != 2 {
                is_log = false;
            }
        }

        // Convert buckets into string instantiation
        let mut buckets_str = buckets
            .iter()
            .map(|(lb, ub)| format!("{{{lb}, {ub}, 0}}"))
            .collect::<Vec<_>>();
        buckets_str.push(format!(
            "{{{}, {}, 0}}",
            buckets.last().unwrap().1,
            u64::MAX
        ));
        let buckets = format!("{{{}}}", buckets_str.join(", "));
        HeaderTemplate {
            name: "hist".into(),
            tmpl_path: [BPF_HEADERS_DIR, "hist.bpf.h.tmpl"]
                .iter()
                .collect::<PathBuf>(),
            ctx: BpfHistogramTemplate {
                n_buckets: buckets.len(),
                buckets,
                is_log,
                fp_scale: FP_SCALE,
            },
        }
    }
}
