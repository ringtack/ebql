pub mod agg;
pub mod compiler;
pub mod hist;
pub mod window;

use std::path::PathBuf;

use serde::Serialize;

pub const BPF_HEADERS_DIR: &str = "./bpf/";
pub const MAX_MEM_BYTES: u64 = 2 << 21;

/// For BPF representations that require an external header, return a header
/// template to be used by the Handlebars template engine.
pub struct HeaderTemplate<C>
where
    C: Serialize,
{
    pub name: String,
    pub tmpl_path: PathBuf,
    pub ctx: C,
}
