//! BPF type and field representations.

use std::{cmp::Ordering, fmt::Display};

/// Representation of a struct field in BPF (C).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    pub _name: String,
    pub _type: Type,

    /// If field is a system variable, record its type (e.g. time, cpu, pid,
    /// etc.). Otherwise, access becomes ctx-><...>.
    // pub _system_var: Option<SystemVar>,

    /// For fields that require access within a struct's array, specify the
    /// array and offset. This is relevant for e.g. syscall tracepoints, where
    /// each field is part of args[].
    /// TODO: migrate this implementation to just read off offset from ctx; this
    /// should remove the need for even knowing the type, since the data
    /// location is already given in the format.
    pub(crate) _arr: Option<String>,
    pub(crate) _off: Option<usize>,
}

impl Field {
    pub fn new(_name: String, _type: Type) -> Field {
        Field {
            _name,
            _type,
            _arr: None,
            _off: None,
        }
    }

    pub fn new_with_off(_name: String, _type: Type, arr: String, off: usize) -> Field {
        Field {
            _name,
            _type,
            _arr: Some(arr),
            _off: Some(off),
        }
    }

    pub fn size(&self) -> usize {
        self._type.size()
    }

    pub fn expr(&self) -> String {
        format!("{self}")
    }
}

impl Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::Type::*;
        match &self._type {
            Bool => write!(f, "bool {}", self._name),
            U8 => write!(f, "u8 {}", self._name),
            U16 => write!(f, "u16 {}", self._name),
            U32 => write!(f, "u32 {}", self._name),
            U64 => write!(f, "u64 {}", self._name),
            S8 => write!(f, "s8 {}", self._name),
            S16 => write!(f, "s16 {}", self._name),
            S32 => write!(f, "s32 {}", self._name),
            S64 => write!(f, "s64 {}", self._name),
            UChar => write!(f, "u8 {}", self._name),
            SChar => write!(f, "s8 {}", self._name),
            String(len) => write!(f, "char {}[{}]", self._name, *len),
            Pointer(t) => write!(f, "{}* {}", *t, self._name),
            Struct(name, _) => write!(f, "{} {}", name, self._name),
        }
    }
}

impl PartialOrd for Field {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Field {
    fn cmp(&self, other: &Self) -> Ordering {
        use self::Type::*;
        match &self._type {
            String(sz1) => {
                match &other._type {
                    String(sz2) => sz1.cmp(&sz2),
                    _ => Ordering::Less,
                }
            }
            _ => {
                match &other._type {
                    String(_) => Ordering::Greater,
                    _ => self.size().cmp(&other.size()),
                }
            }
        }
    }
}

/// Possible data types in BPF (C).
/// Why U/S? vmlinux.h seems to typedef `unsigned <int type>` -> `u#`, and `<int
/// type>` -> `s#`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum Type {
    #[default]
    Bool,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    UChar,
    SChar,
    String(usize),
    // https://www.reddit.com/r/learnrust/comments/171d3cx/self_referential_enumn
    // NOTE: currently, I think this only realy makes sense for one layer of indirection. See if
    // more are necessary.
    Pointer(Box<Type>),
    // TODO: figure out better way to define struct definitions to ensure type safety
    Struct(String, Option<Vec<Type>>),
}

impl Type {
    // Returns the size of the type (in bytes)
    pub fn size(&self) -> usize {
        use self::Type::*;
        match self {
            Bool => 1,
            U8 => 1,
            U16 => 2,
            U32 => 4,
            U64 => 8,
            S8 => 1,
            S16 => 2,
            S32 => 4,
            S64 => 8,
            UChar => 1,
            SChar => 1,
            String(len) => *len,
            Pointer(_) => 8,
            // allow partial definitions to have name
            Struct(_, ot) => {
                match ot {
                    Some(t) => t.iter().map(|t| t.size()).sum(),
                    None => 0,
                }
            }
        }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::Type::*;
        match self {
            Bool => write!(f, "bool"),
            U8 => write!(f, "u8"),
            U16 => write!(f, "u16"),
            U32 => write!(f, "u32"),
            U64 => write!(f, "u64"),
            S8 => write!(f, "s8"),
            S16 => write!(f, "s16"),
            S32 => write!(f, "s32"),
            S64 => write!(f, "s64"),
            UChar => write!(f, "u8"),
            SChar => write!(f, "s8"),
            // TODO: see if I can incorporate this as char <name>[LEN]?
            String(_len) => write!(f, "char *"),
            Pointer(t) => write!(f, "{} *", *t),
            Struct(name, _) => write!(f, "{name}"),
        }
    }
}
