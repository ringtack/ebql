use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use pipeline::*;

use crate::*;

const INCLUDES_STR: &str = "#include \"vmlinux.h\" /* all kernel types */\n\
\n\
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */\n\
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */\n\
#include <bpf/bpf_tracing.h>\n";

const NEWLINE: char = '\n';
const TAB: char = '\t';

pub struct PipelineCompiler {
    pub pipeline: Pipeline,
    pub out_dir: PathBuf,
}

impl PipelineCompiler {
    // Generates eBPF programs for the pipeline
    pub fn generate_programs(&self) -> Result<Vec<PathBuf>> {
        let n_events = self.pipeline.num_events();
        let mut program_texts = Vec::<String>::with_capacity(n_events);
        // For each event, generate the program text corresponding to it
        for (i, event) in self.pipeline.events.iter().enumerate() {
            // TODO: make string builder type and all of the below construction lol
            let mut code = String::new();

            // Create maps for each transformation between events (the last event doesn't
            // need one)
            if i - 1 != n_events {
                code.push_str("struct {");
                code.push(NEWLINE);

                code.push(TAB);
                code.push_str("")

                // TODO: finish
            }
            // Add include texts TODO: more if necessary; but how to see?
            code.push_str(INCLUDES_STR);
            code.push(NEWLINE);

            // Add section
            let sec_text = format!("SEC({})", event.section_name());
            code.push_str(&sec_text);
            code.push(NEWLINE);
        }
        Ok(vec![])
    }
}

pub struct CompilerOutput {
    // TODO: migrate this stuff to an eBPF-specific struct; maybe have compiler output be more
    // generic? Stores output maps for each transformation at each stage
    pub transformation_maps: Vec<HashMap<Field, Field>>,
    // Global variables??
    pub global_variables: Vec<String>,
    // TODO: what else is needed
}
