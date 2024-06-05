use std::{fmt::Display, sync::Arc, time::Duration};

use nom_sql::{ArithmeticExpression, ConditionExpression};

use crate::{events::Event, field::Field, record::DataValue};

#[derive(Clone)]
pub enum Operator {
    /// Creates a window of the specified type.
    Window(WindowType),
    /// Selects from an eBPF event.
    Select(Arc<dyn Event>),
    /// Projects only the specified fields.
    Project(Vec<String>),
    /// Applies the predicate on the specified field.
    Filter(ConditionExpression),
    /// Maps a collection of fields to a new value using the function.
    Map(MapExpression),
    /// Maps in place a field to a new value using the function.
    MapInPlace(String, MapExpression),
    /// Group by keys
    GroupBy(Vec<String>),
    /// Histogram buckets
    Histogram(Vec<(usize, usize)>),
    /// Computes quantile (in percentage form). Currently, must be called over a
    /// histogram.
    Quantile(usize),
    /// Max/min/average/sum field
    Max(String),
    Min(String),
    Average(String),
    Sum(String),
    /// Count either all values, or grouped on a value
    Count(Option<String>),
    /// Join by keys
    Join(Vec<String>),
    DistinctJoin(Vec<String>),
}

impl Display for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operator::Window(wt) => write!(f, "Window({wt})"),
            Operator::Select(e) => write!(f, "Select({})", e.name()),
            Operator::Project(fs) => write!(f, "Project({})", fs.join(", ")),
            Operator::Filter(ce) => write!(f, "Filter({ce})"),
            Operator::Map(me) => write!(f, "Map({me})"),
            Operator::MapInPlace(_, _) => todo!(),
            Operator::GroupBy(_) => todo!(),
            Operator::Histogram(_) => todo!(),
            Operator::Quantile(_) => todo!(),
            Operator::Max(s) => write!(f, "Max({s})"),
            Operator::Min(s) => write!(f, "Min({s})"),
            Operator::Average(s) => write!(f, "Average({s})"),
            Operator::Sum(s) => write!(f, "Sum({s})"),
            Operator::Count(s) => {
                write!(
                    f,
                    "Count({})",
                    match s {
                        Some(s) => s.as_str(),
                        None => "*",
                    }
                )
            }
            Operator::Join(_) => todo!(),
            Operator::DistinctJoin(args) => write!(f, "DistinctJoin({})", args.join(", ")),
        }
    }
}

/// Predicate representation.
#[derive(Clone)]
pub enum Predicate {
    TODO,
}

/// Map expression. For now, only arithmetic on numeric fields is allowed.
#[derive(Clone)]
pub struct MapExpression {
    pub ae: ArithmeticExpression,
    // pub op: ArithmeticOperator,
    // pub left: ArithmeticBase,
    // pub right: ArithmeticBase,
    // pub new_val: String,
}

impl Display for MapExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ae)
    }
}

impl From<ArithmeticExpression> for MapExpression {
    fn from(value: ArithmeticExpression) -> Self {
        MapExpression {
            ae: value.clone(),
            // op: value.ari.op,
            // left: value.ari.left,
            // right: value.ari.right,
            // new_val: value.alias.unwrap(),
        }
    }
}

/// Value reference; can either be actual instantiated data value, or another
/// field.
#[derive(Clone)]
pub enum Ref {
    Field(Field),
    Value(DataValue),
}

/*

Select(event)
Window(WindowType(time | n, step))
Filter(preds)
Map


*/

/// Specifies the window type used to aggregate unbounded streams (i.e. eBPF
/// events) into bounded relations. There are three window types:
/// - Time-based windows (time interval, step)
/// - Data-based windows (size, step)
/// - Session-based windows (inactivity threshold)
///
/// Currently, only tumbling time/count windows are supported in eBPF.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WindowType {
    Time(Duration, Duration),
    Count(usize, usize),
    Session(Duration),
}

impl Display for WindowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowType::Time(interval, step) => {
                write!(
                    f,
                    "Time({})",
                    if interval == step {
                        format!("{:?}", interval)
                    } else {
                        format!("{:?}, {:?}", interval, step)
                    }
                )
            }
            WindowType::Count(count, step) => {
                write!(
                    f,
                    "Count({})",
                    if count == step {
                        format!("{count}")
                    } else {
                        format!("{count}, {step}")
                    }
                )
            }
            WindowType::Session(_) => todo!(),
        }
    }
}
