//! Data type definitions.

use std::{default, fmt};

use crate::{
    field::{FieldRef, Fields},
    types::Type,
};

/// Supported data types in the query schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum DataType {
    #[default]
    Boolean,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    String(usize),
    Timestamp(TimeUnit),
    Struct(String, Fields),
}

impl DataType {
    /// Returns true if the type is numeric.
    #[inline]
    pub fn is_numeric(&self) -> bool {
        use DataType::*;
        matches!(
            self,
            UInt8 | UInt16 | UInt32 | UInt64 | Int8 | Int16 | Int32 | Int64 | Float32 | Float64
        )
    }

    /// Returns true if this type is floating: (Float*).
    pub fn is_floating(&self) -> bool {
        use DataType::*;
        matches!(self, Float32 | Float64)
    }

    /// Returns true if this type is integer: (Int*, UInt*).
    pub fn is_integer(&self) -> bool {
        self.is_signed_integer() || self.is_unsigned_integer()
    }

    /// Returns true if this type is signed integer: (Int*).
    pub fn is_signed_integer(&self) -> bool {
        use DataType::*;
        matches!(self, Int8 | Int16 | Int32 | Int64)
    }

    /// Returns true if this type is unsigned integer: (UInt*).
    pub fn is_unsigned_integer(&self) -> bool {
        use DataType::*;
        matches!(self, UInt8 | UInt16 | UInt32 | UInt64)
    }

    /// Returns true if this type is valid as a dictionary key
    #[inline]
    pub fn is_dictionary_key_type(&self) -> bool {
        self.is_integer()
    }

    /// Compares the datatype with another, ignoring nested field names
    /// and metadata.
    pub fn equals_datatype(&self, other: &DataType) -> bool {
        match (&self, other) {
            (DataType::Struct(s1, a), DataType::Struct(s2, b)) => {
                s1 == s2
                    && a.len() == b.len()
                    && a.iter()
                        .zip(b)
                        .all(|(a, b)| a.data_type().equals_datatype(b.data_type()))
            }
            _ => self == other,
        }
    }

    /// Returns the size of the data type.
    pub fn size(&self) -> usize {
        match self {
            DataType::Boolean => 1,
            DataType::UInt8 => 1,
            DataType::UInt16 => 2,
            DataType::UInt32 => 4,
            DataType::UInt64 => 8,
            DataType::Int8 => 1,
            DataType::Int16 => 2,
            DataType::Int32 => 4,
            DataType::Int64 => 8,
            DataType::Float32 => 4,
            DataType::Float64 => 8,
            DataType::String(len) => *len,
            DataType::Timestamp(_) => 8,
            DataType::Struct(_, fields) => fields.size(),
        }
    }
}

impl Into<Type> for DataType {
    fn into(self) -> Type {
        match self {
            DataType::Boolean => Type::Bool,
            DataType::UInt8 => Type::U8,
            DataType::UInt16 => Type::U16,
            DataType::UInt32 => Type::U32,
            DataType::UInt64 => Type::U64,
            DataType::Int8 => Type::S8,
            DataType::Int16 => Type::S16,
            DataType::Int32 => Type::S32,
            DataType::Int64 => Type::S64,
            DataType::Float32 => unimplemented!("see if bpf supports floats"),
            DataType::Float64 => unimplemented!("see if bpf supports floats"),
            DataType::String(l) => Type::String(l),
            DataType::Timestamp(_) => Type::U64,
            DataType::Struct(name, fields) => {
                Type::Struct(
                    name,
                    Some(
                        fields
                            .iter()
                            .map(|f| f.data_type.clone().into())
                            .collect::<Vec<Type>>(),
                    ),
                )
            }
        }
    }
}

impl From<Type> for DataType {
    fn from(t: Type) -> Self {
        use DataType::*;
        match t {
            Type::Bool => Boolean,
            Type::U8 => UInt8,
            Type::U16 => UInt16,
            Type::U32 => UInt32,
            Type::U64 => UInt64,
            Type::S8 => Int8,
            Type::S16 => Int16,
            Type::S32 => Int32,
            Type::S64 => Int64,
            Type::UChar => UInt8,
            Type::SChar => Int8,
            Type::String(l) => String(l),
            Type::Pointer(_) => unimplemented!("TODO: figure out what to do with pointers"),
            Type::Struct(_, _) => unimplemented!("TODO: figure out what to do with structs"),
        }
    }
}

impl From<&Type> for DataType {
    fn from(t: &Type) -> Self {
        use DataType::*;
        match t {
            Type::Bool => Boolean,
            Type::U8 => UInt8,
            Type::U16 => UInt16,
            Type::U32 => UInt32,
            Type::U64 => UInt64,
            Type::S8 => Int8,
            Type::S16 => Int16,
            Type::S32 => Int32,
            Type::S64 => Int64,
            Type::UChar => UInt8,
            Type::SChar => Int8,
            Type::String(l) => String(*l),
            Type::Pointer(_) => unimplemented!("TODO: figure out what to do with pointers"),
            Type::Struct(_, _) => unimplemented!("TODO: figure out what to do with structs"),
        }
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Unit of time in a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimeUnit {
    /// Time in seconds.
    Second,
    /// Time in milliseconds.
    Millisecond,
    /// Time in microseconds.
    Microsecond,
    /// Time in nanoseconds.
    Nanosecond,
}
