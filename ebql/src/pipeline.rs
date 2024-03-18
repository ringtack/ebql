use anyhow::{anyhow, Result};
use std::{any, collections::HashMap};

pub struct Field {
    pub _name: String,
    pub _type: String,
}

pub struct Pipeline {
    // TODO: how to make this and compiler in the same scope?
    pub events: Vec<TracepointEvent>,
    fields: HashMap<Field, Vec<Field>>,
    filters: Vec<Vec<Filter>>,
    transformations: Vec<Filter>,
}

impl Pipeline {
    pub fn new(
        events: Vec<TracepointEvent>,
        fields: HashMap<Field, Vec<Field>>,
        filters: Vec<Vec<Filter>>,
        transformations: Vec<Filter>,
    ) -> Result<Pipeline> {
        let n_events = events.len();
        // Verify argument structural validity
        if n_events != filters.len() {
            return Err(anyhow!("invalid number of filters"));
        }
        if n_events != transformations.len() - 1 {
            return Err(anyhow!("invalid number of transformations"));
        }
        for (_, mappings) in &fields {
            if mappings.len() != 0 && mappings.len() != n_events {
                return Err(anyhow!("invalid number of field mappings"));
            }
        }

        let pipeline = Pipeline {
            events,
            fields,
            filters,
            transformations,
        };
        Ok(pipeline)
    }

    pub fn num_events(&self) -> usize {
        self.events.len()
    }
}

pub struct TracepointEvent {
    pub path: String,
}

impl TracepointEvent {
    // TODO: when I convert this to a generic Event interface, add better logic
    pub fn section_name(&self) -> String {
        self.path.clone()
    }
}

pub struct Filter {
    pub op: BinOp,
    // TODO: use type checking to ensure field types are equal, if we want to use e.g. constanst
    pub arg1: Field,
    pub arg2: Field, // ig for now here we'll hardcode target_pid.as_str()
}

pub struct Transformation {
    pub name: String,
    pub op: BinOp,
    // TODO: also find structured way to handle this
    pub arg1: Field,
    pub arg2: Field,
}

// TODO: make this an actual Expr / AST style thing
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    NotEq,
}
