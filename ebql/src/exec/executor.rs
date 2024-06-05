use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use crossbeam::channel::Receiver;

use super::{
    bpf_stats::{get_bpf_stats, BpfProgramStats},
    query_stats::{QueryStats, UserspaceStats},
};
use crate::{
    bpf_ops::compiler::QueryCompiler, object::Object, parser, record_batch::RecordBatch,
    PhysicalPlan, Schema,
};

pub struct Executor {
    pub prog_streams: HashMap<String, Receiver<RecordBatch>>,
}

impl Executor {
    pub fn new(obj: Object) -> Result<Self> {
        let mut obj = obj;
        obj.attach_progs()?;

        // Add program streams to hash map
        let mut prog_streams = HashMap::new();

        for (prog_name, prog) in &obj.progs {
            if let Some(out_rx) = &prog.out_rx {
                prog_streams.insert(prog_name.clone(), out_rx.clone());
            }
        }

        Ok(Self { prog_streams })
    }

    pub fn attach(&mut self, obj: Object) -> Result<()> {
        let mut obj = obj;
        obj.attach_progs()?;

        // Add program streams to hash map
        let mut prog_streams = HashMap::new();

        for (prog_name, prog) in &obj.progs {
            if let Some(out_rx) = &prog.out_rx {
                prog_streams.insert(prog_name.clone(), out_rx.clone());
            }
        }

        Ok(())
    }

    /// Executes an extended-SQL query.
    pub fn execute_query(
        &mut self,
        sql_query: String,
    ) -> Result<(Arc<Schema>, Receiver<RecordBatch>)> {
        let s = parser::parse_query(sql_query).context("failed to parse SQL query")?;
        let physical_plan = PhysicalPlan::from_select(s).unwrap();
        let bpf_plan = &physical_plan.event_plans[0];

        let schema = bpf_plan.schema.clone();

        let mut qc = QueryCompiler {};
        let obj = qc.compile_bpf_ops(bpf_plan).unwrap();

        self.attach(obj)?;

        let rx = self.prog_streams.get(&bpf_plan.schema.name).unwrap();

        Ok((schema, rx.clone()))
    }

    pub fn get_program_stats(&self, prog: String) -> Option<QueryStats> {
        let progs = get_bpf_stats()
            .into_iter()
            .filter(|p| p.name == prog)
            .collect::<Vec<_>>();
        let bpf_prog = match progs.len() {
            0 => return None,
            _ => progs[0].clone(),
        };

        Some(QueryStats::new(UserspaceStats::new(), bpf_prog))
    }
}
