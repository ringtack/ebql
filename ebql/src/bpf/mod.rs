//! Raw eBPF representations and interfaces.

/// BPF struct representation.
pub mod bpf_struct;
/// Kernel eBPF events.
pub mod events;
/// Representation of BPF maps, to provide easier interfacing.
pub mod map;
/// Abstract representation of a BPF program. External structs should use this
/// as a handle to interact with relevant BPF fields (e.g. maps, global
/// variables, definitions, etc).
pub mod object;
/// Generic eBPF program builder. Contains helper methods for cleaner eBPF
/// program synthesis.
pub mod prog_builder;
/// Representation of BPF program.
pub mod program;
/// BPF data types and field representations.
pub mod types;

use bpf_struct::*;
use map::*;
use types::*;
