//! Map representation.

use std::{fmt::Display, path::PathBuf};

use super::{Struct, Type};

/// Ring buffer definition.
#[derive(Clone, Debug)]
pub struct RingBuf {
    pub name: String,
    pub s_repr: Struct,
    pub max_entries: usize,
    // TODO: add pinning, flags
}

/// Map definition for creation purposes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapDef {
    pub name: String,
    pub map_type: MapType,
    // TODO: this should really be restricted to integer types
    pub key_type: Type,
    pub value_type: String,
    pub max_entries: u64,
    pub flags: MapDefFlags,
    // Optionally pin
    pub pin: Option<PathBuf>,
}

/// Map type representation; don't use libbpf's, since the to string
/// representation is off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
// TODO: expand
pub enum MapType {
    Hash = 1,
    Array = 2,
    RingBuffer = 27,
}

impl MapType {
    pub fn to_libbpf_map_type(&self) -> libbpf_rs::MapType {
        match self {
            MapType::RingBuffer => libbpf_rs::MapType::RingBuf,
            MapType::Hash => libbpf_rs::MapType::Hash,
            MapType::Array => libbpf_rs::MapType::Array,
        }
    }
}
impl Display for MapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MapType::RingBuffer => write!(f, "BPF_MAP_TYPE_RINGBUF"),
            MapType::Hash => write!(f, "BPF_MAP_TYPE_HASH"),
            MapType::Array => write!(f, "BPF_MAP_TYPE_ARRAY"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapDefFlags {
    pub val: u64,
}

impl MapDefFlags {
    pub fn new() -> Self {
        Self { val: 0 }
    }

    pub fn no_prealloc(self) -> Self {
        // In vmlinux.h's definition of BPF_F_NO_PREALLOC = 1
        Self { val: self.val | 1 }
    }

    pub fn mmapable(self) -> Self {
        // In vmlinux.h's definition of BPF_F_MMAPABLE = 2048
        Self {
            val: self.val | 2048,
        }
    }
}
