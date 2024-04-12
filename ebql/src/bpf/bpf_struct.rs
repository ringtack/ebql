use std::{str, sync::Arc};

use anyhow::Result;

use super::{Field, Type};
use crate::{
    record::{DataValue, Record},
    schema::schema::Schema,
};

/// Representation of a struct in BPF (C).
#[derive(Clone, Debug)]
pub struct Struct {
    pub name: String,
    pub fields: Vec<Field>,
    pub sz: usize,
    pub offs: Vec<usize>,
    /// Reference to schema defining this struct
    pub schema: Arc<Schema>,
    /// Map sorted offsets to original offsets
    mapping: Vec<usize>,
}

impl Struct {
    /// Initializes a BPF struct with the specified fields. To optimize padding,
    /// specify with the flag.
    pub fn new(name: String, fields: Vec<Field>, schema: Arc<Schema>, optimize: bool) -> Self {
        let mut s = Self {
            name,
            fields: fields.clone(),
            offs: vec![0; fields.len()],
            sz: 0,
            schema,
            mapping: vec![0; fields.len()],
        };
        if optimize {
            s.optimize_padding();
        }
        // Populate size and offsets of s
        s.sz = s.populate_offsets(optimize);
        s
    }

    /// Returns the fields, together with their byte offsets.
    pub fn field_offsets(&self) -> Vec<(Field, usize)> {
        self.fields
            .clone()
            .into_iter()
            .zip(self.offs.clone().into_iter())
            .collect::<Vec<_>>()
    }

    /// Optimizes the padding of the struct's fields.
    fn optimize_padding(&mut self) {
        self.fields.sort_by(|a, b| b.cmp(a));
        // After sorting, iterate through fields and find its associated field in the
        // schema
        self.fields.iter().enumerate().for_each(|(i, f)| {
            self.mapping[i] = self
                .schema
                .fields
                .iter()
                .position(|sf| f._name == sf.name)
                .unwrap();
        });
    }

    /// Populates the offsets of the struct with the actual offset values.
    /// Returns the size the bpf struct will be in C.
    fn populate_offsets(&mut self, sorted: bool) -> usize {
        // Resize if necessary to ensure no OOB access
        self.offs.resize(self.fields.len(), 0);

        // Sortedness determines if we can quickly find the largest value
        let max = if sorted {
            self.fields[0].size()
        } else {
            self.fields.iter().max().unwrap().size()
        };
        let mut off = 0;
        // For each field, add its size (plus padding contributions), and populate its
        // offset
        for (i, f) in self.fields.iter().enumerate() {
            let fsz = f.size();
            // Check if this field needs a gap (i.e. curr off not divisible by fsz, and not
            // a string)
            let need_gap_before = off % fsz;
            if !matches!(f._type, Type::String { .. }) && need_gap_before != 0 {
                // If so, cover up the remainder
                off += fsz - need_gap_before;
            }
            // Populate offset
            self.offs[i] = off;
            // Increment by value
            off += fsz;
        }
        // Make sure to add for the remaining padding necessary
        if off % max != 0 {
            off += max - off % max;
        }
        off
    }

    /// Attempts to convert a byte slice into the output Record, specified by
    /// the struct's schema.
    pub fn produce_record(&self, buf: &[u8]) -> Result<Record> {
        let mut dvs = vec![DataValue::Boolean(false); self.fields.len()];
        // For each field, convert to data value
        for (i, f) in self.fields.iter().enumerate() {
            // Get its offset within the buf
            let start = self.offs[i];
            let end = start + f.size();

            // log::info!("Reading buf[{}..{}] for type {}", start, end, f._type);

            let f_buf = &buf[start..end];
            // Based on the field's data type, transmute it to the appropriate type
            let dv = match f._type {
                Type::Bool => {
                    let val = f_buf[0] != 0;
                    DataValue::Boolean(val)
                }
                Type::U8 | Type::UChar => DataValue::UInt8(f_buf[0]),
                Type::U16 => {
                    let val =
                        unsafe { std::mem::transmute::<[u8; 2], u16>(f_buf.try_into().unwrap()) };
                    DataValue::UInt16(val)
                }
                Type::U32 => {
                    let val =
                        unsafe { std::mem::transmute::<[u8; 4], u32>(f_buf.try_into().unwrap()) };
                    DataValue::UInt32(val)
                }
                Type::U64 => {
                    let val =
                        unsafe { std::mem::transmute::<[u8; 8], u64>(f_buf.try_into().unwrap()) };
                    DataValue::UInt64(val)
                }
                Type::S8 | Type::SChar => DataValue::Int8(f_buf[0] as i8),
                Type::S16 => {
                    let val =
                        unsafe { std::mem::transmute::<[u8; 2], i16>(f_buf.try_into().unwrap()) };
                    DataValue::Int16(val)
                }
                Type::S32 => {
                    let val =
                        unsafe { std::mem::transmute::<[u8; 4], i32>(f_buf.try_into().unwrap()) };
                    DataValue::Int32(val)
                }
                Type::S64 => {
                    let val =
                        unsafe { std::mem::transmute::<[u8; 8], i64>(f_buf.try_into().unwrap()) };
                    DataValue::Int64(val)
                }
                Type::String(len) => {
                    let s = str::from_utf8(f_buf)?;
                    DataValue::String(s.to_string(), len)
                }
                Type::Pointer(_) => unimplemented!("dunno how to handle this"),
                Type::Struct(_, _) => unimplemented!("dunno how to handle this"),
            };

            // Assign mapping from optimized representation order to schema order
            dvs[self.mapping[i]] = dv;
        }

        Ok(Record::from(dvs))
    }
}
