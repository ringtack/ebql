//! Field (a single "column" in the schema) representation.

use std::{fmt, ops::Deref, sync::Arc};

use anyhow::{bail, Result};
use nom_sql::Column;

use crate::{
    data_types::DataType,
    events::{get_event_field, Event},
    types,
};

/// Reference to a Field
/// TODO: Arc or just Rc?
pub type FieldRef = Arc<Field>;

/// Collection of fields.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Fields(Arc<[FieldRef]>);
impl Fields {
    /// Returns a new empty [`Fields`]
    pub fn empty() -> Self {
        Self(Arc::new([]))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return size of this instance in bytes.
    pub fn size(&self) -> usize {
        self.iter().map(|field| field.size()).sum()
    }

    /// Converts a collection of fields into a list of BPF fields at an event.
    pub fn to_bpf_fields(&self, e: &Arc<dyn Event>) -> Vec<types::Field> {
        self.0
            .iter()
            .map(|f| {
                match get_event_field(e, &f.name) {
                    Some(f) => f,
                    None => {
                        types::Field {
                            _name: f.name.clone(),
                            _type: f.data_type.clone().into(),
                            _arr: None,
                            _off: None,
                        }
                    }
                }
            })
            .collect()
    }
}

impl Default for Fields {
    fn default() -> Self {
        Self::empty()
    }
}

impl FromIterator<Field> for Fields {
    fn from_iter<T: IntoIterator<Item = Field>>(iter: T) -> Self {
        iter.into_iter().map(Arc::new).collect()
    }
}

impl FromIterator<FieldRef> for Fields {
    fn from_iter<T: IntoIterator<Item = FieldRef>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl From<Vec<Field>> for Fields {
    fn from(value: Vec<Field>) -> Self {
        value.into_iter().collect()
    }
}

impl From<Vec<FieldRef>> for Fields {
    fn from(value: Vec<FieldRef>) -> Self {
        Self(value.into())
    }
}

impl From<&[FieldRef]> for Fields {
    fn from(value: &[FieldRef]) -> Self {
        Self(value.into())
    }
}

impl<const N: usize> From<[FieldRef; N]> for Fields {
    fn from(value: [FieldRef; N]) -> Self {
        Self(Arc::new(value))
    }
}

impl Deref for Fields {
    type Target = [FieldRef];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<'a> IntoIterator for &'a Fields {
    type IntoIter = std::slice::Iter<'a, FieldRef>;
    type Item = &'a FieldRef;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl std::fmt::Debug for Fields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.as_ref().fmt(f)
    }
}

impl fmt::Display for Fields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Fields({})",
            self.0
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Describes a single "column" in a schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Field {
    pub name: String,
    pub data_type: DataType,
}

impl Field {
    /// Returns an immutable reference to the `Field`'s name.
    #[inline]
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Computes the size of the field.
    #[inline]
    pub fn size(&self) -> usize {
        self.data_type.size()
    }

    /// Returns an immutable reference to the [`Field`]'s  [`DataType`].
    #[inline]
    pub fn data_type(&self) -> &DataType {
        &self.data_type
    }

    /// Set [`DataType`] of the [`Field`] and returns self.
    pub fn with_data_type(mut self, data_type: DataType) -> Self {
        self.data_type = data_type;
        self
    }
}

impl From<types::Field> for Field {
    fn from(value: types::Field) -> Self {
        Self {
            name: value._name,
            data_type: DataType::from(value._type),
        }
    }
}

impl From<&types::Field> for Field {
    fn from(value: &types::Field) -> Self {
        Self {
            name: value._name.clone(),
            data_type: DataType::from(&value._type),
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.data_type)
    }
}
