//

use std::{fmt::Display, ops::Deref, sync::Arc, time::Duration};

use nom_sql::Literal;

use crate::data_types::{DataType, TimeUnit};

/// Record representation.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Record(Vec<DataValue>);

impl Record {
    /// Returns a new empty [`Record`]
    pub fn empty() -> Self {
        Self(vec![])
    }

    /// Gets the length of this record (i.e. # columns)
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return size of this instance in bytes.
    pub fn size(&self) -> usize {
        self.iter().map(|dv| dv.size()).sum()
    }
}

impl Default for Record {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<DataValue>> for Record {
    fn from(value: Vec<DataValue>) -> Self {
        Record(value)
    }
}

impl From<&[DataValue]> for Record {
    fn from(value: &[DataValue]) -> Self {
        Self(value.into())
    }
}

impl Deref for Record {
    type Target = [DataValue];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<'a> IntoIterator for &'a Record {
    type IntoIter = std::slice::Iter<'a, DataValue>;
    type Item = &'a DataValue;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Record({})",
            self.0
                .iter()
                .map(|dv| dv.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, Hash)]
pub enum DataValue {
    Boolean(bool),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    String(String, usize),
    Timestamp(Duration),
    // TODO: implement nested data values later
    // Struct(Fields),
    // TODO: implement
    // Float32(f32),
    // Float64(f64),
}

impl DataValue {
    /// Computes the size of the field.
    #[inline]
    pub fn size(&self) -> usize {
        match self {
            DataValue::Boolean(_) => 1,
            DataValue::UInt8(_) => 1,
            DataValue::UInt16(_) => 2,
            DataValue::UInt32(_) => 4,
            DataValue::UInt64(_) => 8,
            DataValue::Int8(_) => 1,
            DataValue::Int16(_) => 2,
            DataValue::Int32(_) => 4,
            DataValue::Int64(_) => 8,
            DataValue::String(_, l) => *l,
            DataValue::Timestamp(_) => 8,
        }
    }

    /// Gets the [`DataValue`]'s  [`DataType`].
    #[inline]
    pub fn data_type(&self) -> DataType {
        use DataValue::*;
        match self {
            Boolean(_) => DataType::Boolean,
            UInt8(_) => DataType::UInt8,
            UInt16(_) => DataType::UInt16,
            UInt32(_) => DataType::UInt32,
            UInt64(_) => DataType::UInt64,
            Int8(_) => DataType::Int8,
            Int16(_) => DataType::Int16,
            Int32(_) => DataType::Int32,
            Int64(_) => DataType::Int64,
            String(_, l) => DataType::String(*l),
            Timestamp(_) => DataType::Timestamp(TimeUnit::Nanosecond),
        }
    }
}

impl From<Literal> for DataValue {
    fn from(l: Literal) -> Self {
        match l {
            Literal::Integer(i) => DataValue::Int64(i),
            Literal::UnsignedInteger(u) => DataValue::UInt64(u),
            Literal::String(s) => DataValue::String(s.clone(), s.len()),
            _ => unimplemented!("literal {} not supported", l.to_string()),
        }
    }
}

impl PartialEq for DataValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Boolean(l0), Self::Boolean(r0)) => l0 == r0,
            (Self::UInt8(l0), Self::UInt8(r0)) => l0 == r0,
            (Self::UInt16(l0), Self::UInt16(r0)) => l0 == r0,
            (Self::UInt32(l0), Self::UInt32(r0)) => l0 == r0,
            (Self::UInt64(l0), Self::UInt64(r0)) => l0 == r0,
            (Self::Int8(l0), Self::Int8(r0)) => l0 == r0,
            (Self::Int16(l0), Self::Int16(r0)) => l0 == r0,
            (Self::Int32(l0), Self::Int32(r0)) => l0 == r0,
            (Self::Int64(l0), Self::Int64(r0)) => l0 == r0,
            (Self::String(l0, _), Self::String(r0, _)) => l0 == r0,
            (Self::Timestamp(l0), Self::Timestamp(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for DataValue {}

impl std::fmt::Display for DataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DataValue::Boolean(b) => write!(f, "{b}"),
            DataValue::UInt8(u) => write!(f, "{u}"),
            DataValue::UInt16(u) => write!(f, "{u}"),
            DataValue::UInt32(u) => write!(f, "{u}"),
            DataValue::UInt64(u) => write!(f, "{u}"),
            DataValue::Int8(i) => write!(f, "{i}"),
            DataValue::Int16(i) => write!(f, "{i}"),
            DataValue::Int32(i) => write!(f, "{i}"),
            DataValue::Int64(i) => write!(f, "{i}"),
            DataValue::String(s, _) => write!(f, "{s}"),
            DataValue::Timestamp(d) => write!(f, "{:?}", d),
        }
    }
}
