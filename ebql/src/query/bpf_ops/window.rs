use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, Result};
use serde::Serialize;

use super::{HeaderTemplate, BPF_HEADERS_DIR};
use crate::query::operators::WindowType;

/// BPF window implementations.
pub enum BpfWindowType {
    TumblingCountWindow(usize),
    TumblingTimeWindow(Duration),
}

#[derive(Serialize)]
pub struct BpfWindowTemplate {
    query_name: String,
    is_count: bool,
    count: usize,
    interval: u64,
}

impl BpfWindowType {
    pub fn get_tmpl(&self, name: String, has_aggs: bool) -> HeaderTemplate<BpfWindowTemplate> {
        let (is_count, count, interval_ns) = match self {
            BpfWindowType::TumblingCountWindow(n) => (true, *n, 0),
            BpfWindowType::TumblingTimeWindow(dur) => (false, 1 << 15, dur.as_nanos() as u64),
        };

        let window_type = if has_aggs {
            "tumbling_window"
        } else {
            "stateful_window"
        };
        HeaderTemplate {
            name: window_type.to_string(),
            tmpl_path: [BPF_HEADERS_DIR, &format!("{window_type}.bpf.h.tmpl")]
                .iter()
                .collect::<PathBuf>(),
            ctx: BpfWindowTemplate {
                query_name: name,
                is_count,
                count,
                interval: interval_ns,
            },
        }
    }
}

impl TryFrom<&WindowType> for BpfWindowType {
    type Error = anyhow::Error;

    fn try_from(wt: &WindowType) -> Result<Self> {
        match wt {
            WindowType::Time(iv, step) => {
                if *iv == *step {
                    Ok(Self::TumblingTimeWindow(*iv))
                } else {
                    Err(anyhow!(
                        "Non-tumbling step windows not supported in BPF yet"
                    ))
                }
            }
            WindowType::Count(n, step) => {
                if *n == *step {
                    Ok(Self::TumblingCountWindow(*n))
                } else {
                    Err(anyhow!(
                        "Non-tumbling step windows not supported in BPF yet"
                    ))
                }
            }
            WindowType::Session(_) => Err(anyhow!("Session windows not supported in BPF yet")),
        }
    }
}
