use std::path::PathBuf;

use anyhow::{bail, Ok};
use libbpf_rs::{Link, Object, ObjectBuilder, RingBuffer, RingBufferBuilder};

use crate::{bpf_gen::*, bpf_types::*};

// Select at a specific event.
pub struct BpfSelect {
    pub event: TracepointEvent,
    pub fields: Vec<Field>,
}

// Handler to interact with outputted BPF program
#[derive(Debug)]
pub struct SelectProgramHandler {
    pub file: PathBuf,
    pub rb: RingBufferRepr,
    pub s_repr: StructRepr,

    obj: Option<Object>,
}

impl SelectProgramHandler {
    pub fn new(file: PathBuf, rb: RingBufferRepr, s_repr: StructRepr) -> Self {
        Self {
            file,
            rb,
            s_repr,
            obj: None,
        }
    }

    pub fn load_and_attach(&mut self) -> Vec<Link> {
        // Using the handler, open the BPF object. We won't do any pre-loading here, but
        // there are possible configuration options here that might be helpful later
        // (e.g. for setting const volatile variables)
        let open_obj = ObjectBuilder::default().open_file(&self.file).unwrap();
        let mut obj = open_obj.load().unwrap();
        // Attach all programs
        let links = obj
            .progs_iter_mut()
            .map(|prog| prog.attach().unwrap())
            .collect::<Vec<_>>();

        self.obj = Some(obj);
        links
    }

    pub fn get_ring_buffer(&mut self) -> anyhow::Result<RingBuffer> {
        // Create handler based on struct definition

        let process_event = self.create_event_handler();
        if self.obj.is_none() {
            bail!("libbpf object not currently initialized")
        }
        // Unwrap is safe, since we already checked
        let obj = self.obj.as_mut().unwrap();

        // Build ring buffer from map
        let mut rb = RingBufferBuilder::new();
        rb.add(obj.map_mut(&self.rb.name).unwrap(), process_event)?;
        let rb = rb.build()?;
        Ok(rb)
    }

    pub fn create_event_handler(&self) -> impl FnMut(&[u8]) -> i32 {
        let s_repr = self.s_repr.clone();
        let process_event = move |buf: &[u8]| {
            println!("handling buf of size {}", buf.len());
            // Validate size
            let total_sz = s_repr.total_size();
            if buf.len() < total_sz {
                println!("got buf len {}, struct size {}", buf.len(), total_sz);
                return 1;
            }

            // Extract value for each field
            print!("{}: ", s_repr.name);
            let mut pos = 0;
            for field in &s_repr.fields {
                match field._type {
                    Type::U8 | Type::UChar | Type::SChar => {
                        let val = buf[pos];
                        print!("{}, ", val);
                    }
                    Type::U16 => {
                        let val = unsafe {
                            std::mem::transmute::<[u8; 2], u16>(
                                buf[pos..pos + 2].try_into().unwrap(),
                            )
                        };
                        print!("{}, ", val);
                    }
                    Type::U32 => {
                        let val = unsafe {
                            std::mem::transmute::<[u8; 4], u32>(
                                buf[pos..pos + 4].try_into().unwrap(),
                            )
                        };
                        print!("{}, ", val);
                    }
                    Type::U64 => {
                        let val = unsafe {
                            std::mem::transmute::<[u8; 8], u64>(
                                buf[pos..pos + 8].try_into().unwrap(),
                            )
                        };
                        print!("{}, ", val);
                    }
                    Type::S8 => {}
                    Type::S16 => {
                        let val = unsafe {
                            std::mem::transmute::<[u8; 2], i16>(
                                buf[pos..pos + 2].try_into().unwrap(),
                            )
                        };
                        print!("{}, ", val);
                    }
                    Type::S32 => {
                        let val = unsafe {
                            std::mem::transmute::<[u8; 4], i32>(
                                buf[pos..pos + 4].try_into().unwrap(),
                            )
                        };
                        print!("{}, ", val);
                    }
                    Type::S64 => {
                        let val = unsafe {
                            std::mem::transmute::<[u8; 8], i64>(
                                buf[pos..pos + 8].try_into().unwrap(),
                            )
                        };
                        print!("{}, ", val);
                    }
                    Type::String(_) => {
                        unimplemented!("TODO this will be a little trickier maybe")
                    }
                }
                pos += field._type.size();
            }
            println!();
            println!("pos: {}, total_sz: {}", pos, total_sz);
            0
        };

        process_event
    }
}
