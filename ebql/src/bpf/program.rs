//! BPF Program map representation.

use std::collections::HashMap;

use crossbeam::channel::Receiver;
use libbpf_rs::Link;

use super::Struct;
use crate::{map::RingBuf, prog_builder::Expr, record_batch::RecordBatch};

/// Handle over an individual BPF program.
pub struct Program {
    /// List of struct definitions in the program
    /// TODO: include this only if necessary
    pub structs: HashMap<String, Struct>,
    /// List of globals in the program.
    pub globals: HashMap<String, Expr>,
    /// Ring buffer
    pub ring_buffer: RingBuf,
    /// Program link
    pub link: Option<Link>,
    /// Output receiver channel for events
    pub out_rx: Option<Receiver<RecordBatch>>,
}

impl Program {
    /// Construct a program.
    pub fn new(
        structs: HashMap<String, Struct>,
        globals: HashMap<String, Expr>,
        ring_buffer: RingBuf,
    ) -> Self {
        Self {
            structs,
            globals,
            ring_buffer,
            link: None,
            out_rx: None,
        }
    }

    /// Add attached information to this program
    pub fn add_attach_info(&mut self, link: Link, out_rx: Receiver<RecordBatch>) {
        self.link = Some(link);
        self.out_rx = Some(out_rx);
    }
}
