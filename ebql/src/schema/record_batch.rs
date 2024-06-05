use std::{fmt::Display, sync::Arc};

use super::schema::Schema;
use crate::record::Record;

/// A batch of records.
pub struct RecordBatch {
    pub schema: Arc<Schema>,
    pub records: Vec<Record>,
}

impl RecordBatch {
    /// Creates a new [`RecordBatch`] from the schema definition and list of
    /// records.
    pub fn new(schema: Arc<Schema>, records: Vec<Record>) -> Self {
        Self { schema, records }
    }

    /// Gets the length of this record (i.e. # records)
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Return size of this record batch in bytes.
    pub fn size(&self) -> usize {
        self.records.iter().map(|r| r.size()).sum()
    }
}

impl Display for RecordBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut records = Vec::new();
        for record in &self.records {
            let mut record_str = String::from("[");
            let mut i = 0;
            for f in self.schema.fields.iter() {
                record_str.push_str(&format!("{}: {}", f.name, record.get(i)));
                i += 1;
                if i != self.schema.fields.len() {
                    record_str.push_str(", ")
                }
            }
            record_str.push(']' as char);
            records.push(record_str);
        }

        write!(f, "RecordBatch(\n\t{}\n)", records.join("\n\t"))
    }
}

impl<'a> IntoIterator for &'a RecordBatch {
    type IntoIter = std::slice::Iter<'a, Record>;
    type Item = &'a Record;

    fn into_iter(self) -> Self::IntoIter {
        self.records.iter()
    }
}
