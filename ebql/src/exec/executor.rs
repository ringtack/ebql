use std::collections::HashMap;

use anyhow::{Context, Result};
use crossbeam::channel::Receiver;

use crate::{object::Object, record_batch::RecordBatch, schema::schema::Schema};

pub struct Executor {
    pub obj: Object,
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

        Ok(Self { obj, prog_streams })
    }
}
