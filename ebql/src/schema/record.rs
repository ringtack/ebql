//

use std::{ops::Deref, sync::Arc, time::Duration};

use crate::data_types::{DataType, TimeUnit};

/// Record representation.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Record(Arc<[DataValue]>);

impl Record {
    /// Returns a new empty [`Record`]
    pub fn empty() -> Self {
        Self(Arc::new([]))
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

impl FromIterator<DataValue> for Record {
    fn from_iter<T: IntoIterator<Item = DataValue>>(iter: T) -> Self {
        iter.into_iter().collect()
    }
}

impl From<Vec<DataValue>> for Record {
    fn from(value: Vec<DataValue>) -> Self {
        value.into_iter().collect()
    }
}

impl From<&[DataValue]> for Record {
    fn from(value: &[DataValue]) -> Self {
        Self(value.into())
    }
}

impl<const N: usize> From<[DataValue; N]> for Record {
    fn from(value: [DataValue; N]) -> Self {
        Self(Arc::new(value))
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
        self.0.as_ref().fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl std::fmt::Display for DataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
