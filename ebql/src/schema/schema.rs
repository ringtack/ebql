use std::{fmt::Display, sync::Arc};

use anyhow::Result;

use crate::{bpf_struct::Struct, events::Event, field::Fields};

/// Data schema definition.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Schema {
    /// Optional name of the schema
    pub name: String,
    /// Fields of the schema
    pub fields: Fields,
}

impl Schema {
    /// Create a schema with the specified name and fields.
    pub fn new(name: Option<String>, fields: Fields) -> Self {
        Self {
            name: name.unwrap_or_default(),
            fields,
        }
    }

    /// Project the specified field indices into another schema.
    pub fn project_indices(&self, indices: &[usize]) -> Schema {
        Schema {
            name: self.name.clone(),
            fields: indices.iter().map(|i| self.fields[*i].clone()).collect(),
        }
    }

    /// Project the specified field names to another schema.
    // pub fn project_fields(&self, names: &[&str]) -> Schema {
    // }

    /// Tries to convert schema into a BpfStruct representation.
    pub fn to_bpf_struct(self: Arc<Self>, e: &Arc<dyn Event>) -> Result<Struct> {
        let fields = self.fields.to_bpf_fields(e);

        Ok(Struct::new(
            format!("{}_t", self.name.clone()),
            fields,
            self.clone(),
            true,
        ))
    }
}

impl Display for Schema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[Query: {}, Fields: {:?}]", self.name, self.fields)
    }
}
