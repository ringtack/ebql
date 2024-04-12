use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use daggy::{Dag, NodeIndex};

use super::operators::Operator;
use crate::{events::Event, schema::schema::Schema};

/// Logical plan representation.
pub struct LogicalPlan<S = Base> {
    pub op_graph: Dag<Arc<Schema>, Operator>,

    /// Map of event name -> node index
    pub events: HashMap<String, NodeIndex>,

    _marker: PhantomData<S>,
}

impl LogicalPlan<Base> {
    pub fn new() -> Self {
        Self {
            op_graph: Dag::new(),
            events: HashMap::new(),
            _marker: PhantomData,
        }
    }

    // TODO: implement operator additions
    // TODO:
    // pub fn select(&self, )

    pub fn join(&mut self, e1: &Box<dyn Event>, e2: &Box<dyn Event>) -> &mut Self {
        todo!()
    }

    /// Verify data types are coherent.
    pub fn verify(&self) -> bool {
        todo!()
    }
}

// State transitions
#[derive(Clone, Copy, Debug, Default)]
pub struct Base;
#[derive(Clone, Copy, Debug)]
pub struct Stream;
#[derive(Clone, Copy, Debug)]
pub struct Relation;
