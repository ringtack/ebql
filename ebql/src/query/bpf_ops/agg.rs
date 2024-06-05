use std::path::PathBuf;

use anyhow::{anyhow, Result};
use serde::Serialize;

use super::{HeaderTemplate, BPF_HEADERS_DIR};
use crate::{query::operators::Operator, types};

#[derive(Serialize, Default)]
pub struct BpfAggregateTemplate {
    pub query_name: String,
    pub gb_max_entries: u64,
    pub avg_scale: u64,
    pub group_bys: Vec<GroupBy>,
    pub aggs: Vec<Agg>,
}

const AVG_SCALE: u64 = 1e6 as u64;

impl BpfAggregateTemplate {
    pub fn new(
        query_name: String,
        group_bys: &[types::Field],
    ) -> HeaderTemplate<BpfAggregateTemplate> {
        let gb_max_entries = get_max_entries(&group_bys);
        let group_bys = group_bys
            .iter()
            .map(|f| {
                GroupBy {
                    field_name: f._name.clone(),
                    field_type: f._type.to_string(),
                }
            })
            .collect::<Vec<_>>();
        // TODO: this is so ugly lmfao
        // ... and it doesn't even work, since code gen will try to access a dummy var
        // if group_bys.is_empty() {
        //     group_bys.push(GroupBy {
        //         field_name: "dummy".to_string(),
        //         field_type: "u8".to_string(),
        //     });
        // }
        HeaderTemplate {
            name: "agg".into(),
            tmpl_path: [BPF_HEADERS_DIR, "agg.bpf.h.tmpl"]
                .iter()
                .collect::<PathBuf>(),
            ctx: BpfAggregateTemplate {
                query_name,
                gb_max_entries,
                group_bys,
                avg_scale: AVG_SCALE,
                aggs: Vec::new(),
            },
        }
    }

    pub fn update(&mut self, op: &Operator) -> Result<()> {
        // If group bys are empty and operator isn't count(*), error
        if self.group_bys.is_empty() && !matches! {op, Operator::Count(None)} {
            return Err(anyhow!(
                "Attempted to call aggregation {op} without group bys"
            ));
        }
        let agg = match op {
            Operator::Max(f) => {
                Agg {
                    is_avg: false,
                    agg: "max".into(),
                    field_name: f.clone(),
                    query_name: self.query_name.clone(),
                }
            }
            Operator::Min(f) => {
                Agg {
                    is_avg: false,
                    agg: "min".into(),
                    field_name: f.clone(),
                    query_name: self.query_name.clone(),
                }
            }
            Operator::Average(f) => {
                Agg {
                    is_avg: true,
                    agg: "avg".into(),
                    field_name: f.clone(),
                    query_name: self.query_name.clone(),
                }
            }
            Operator::Sum(f) => {
                Agg {
                    is_avg: false,
                    agg: "sum".into(),
                    field_name: f.clone(),
                    query_name: self.query_name.clone(),
                }
            }
            Operator::Count(Some(f)) => {
                Agg {
                    is_avg: false,
                    agg: "count".into(),
                    field_name: f.clone(),
                    query_name: self.query_name.clone(),
                }
            }
            Operator::Count(None) => {
                Agg {
                    is_avg: false,
                    agg: "count".into(),
                    field_name: String::new(),
                    query_name: self.query_name.clone(),
                }
            }
            _ => return Err(anyhow!("Got operator non-supported aggregation {op}")),
        };
        self.aggs.push(agg);
        Ok(())
    }
}

#[derive(Serialize, Default)]
pub struct GroupBy {
    pub field_name: String,
    pub field_type: String,
}

#[derive(Serialize, Default)]
pub struct Agg {
    pub is_avg: bool,
    pub agg: String,
    pub field_name: String,
    pub query_name: String,
}

const GB_MAX_ENTRIES: u64 = 1 << 14; // 16384
fn get_max_entries(gbs: &[types::Field]) -> u64 {
    if gbs.len() == 1 {
        let field = &gbs[0];
        if field._name == "cpu" {
            return std::thread::available_parallelism().unwrap().get() as u64;
        }
    }
    // TODO: find way to compute
    GB_MAX_ENTRIES
}
