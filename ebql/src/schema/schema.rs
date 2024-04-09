use std::sync::Arc;

use anyhow::Result;

use crate::{bpf_struct::Struct, events::Event, field::Fields};

/// Data schema definition.
#[derive(Clone, Debug)]
pub struct Schema {
    /// Optional name of the schema
    pub name: String,
    /// Fields of the schema
    pub fields: Fields,
}

impl Schema {
    /// Create a schema with the specified name and
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
    pub fn to_bpf_struct(self: Arc<Self>, e: &Box<dyn Event>) -> Result<Struct> {
        let fields = self.fields.to_bpf_fields(e)?;

        Ok(Struct::new(self.name.clone(), fields, self.clone(), true))
    }
}
