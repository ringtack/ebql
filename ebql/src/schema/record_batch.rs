use std::sync::Arc;

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

impl<'a> IntoIterator for &'a RecordBatch {
    type IntoIter = std::slice::Iter<'a, Record>;
    type Item = &'a Record;

    fn into_iter(self) -> Self::IntoIter {
        self.records.iter()
    }
}
