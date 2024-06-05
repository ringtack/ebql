use std::{collections::HashMap, fmt, sync::Arc};

use anyhow::{Context, Result};
use daggy::Walker;
use nom_sql::{
    Column, ConditionBase, ConditionExpression, FieldDefinitionExpression, FunctionArgument,
    FunctionExpression, JoinConstraint, JoinOperator, JoinRightSide, SelectStatement,
};
use rand::distributions::{Alphanumeric, DistString};

use super::operators::{Operator, WindowType};
use crate::{
    events::{get_event, Event},
    field::Field,
    schema::schema::Schema,
    types::{self, Type},
};

#[derive(Default)]
pub struct EventPlan {
    /// Bpf plans to compile (should only have 1, or 2 if join)
    pub bpf_plans: Vec<BpfPlan>,
    /// Which physical operators to execute within user space.
    user_ops: Vec<Operator>,

    /// Schema of emitted values between user<->kernel space
    /// TODO: prob not necessary since encoded in record batch? but might need
    /// during compilation
    schema: Arc<Schema>,
}

#[derive(Clone)]
pub struct BpfPlan {
    /// Schema definition. For stateless processing / aggregations / joins, this
    /// is the only schema used. For joins, this is the input schema.
    pub schema: Arc<Schema>,

    /// Event on which the BPF plan is executing
    pub event: Arc<dyn Event>,

    /// Window expression
    pub window: Option<WindowType>,
    /// Fields to project
    pub projects: Vec<types::Field>,
    /// Stateless operators
    pub filters: Option<Operator>,
    pub maps: Vec<Operator>,
    /// Fields on which to group by
    pub group_by: Vec<types::Field>,
    /// Aggregations to execute.
    pub aggs: Vec<Operator>,

    // Whether is distinct
    pub distinct: bool,
    // If a distinct join occurs, get the two input schemas and fields on which to join
    pub distinct_join: Option<BpfJoin>,
}

impl fmt::Debug for BpfPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BpfPlan")
            .field("schema", &self.schema)
            .field("event", &self.event.name())
            .field("window", &self.window)
            .field("projects", &self.projects)
            .field(
                "filters",
                &match &self.filters {
                    Some(o) => format!("Some({o})"),
                    None => String::from("None"),
                },
            )
            .field(
                "maps",
                &self
                    .maps
                    .iter()
                    .map(|op| op.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .field("group_by", &self.group_by)
            .field(
                "aggs",
                &self
                    .aggs
                    .iter()
                    .map(|op| op.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .field("distinct", &self.distinct)
            .field("distinct_join", &self.distinct_join)
            .finish()
    }
}

impl BpfPlan {
    pub fn new(e: &Arc<dyn Event>) -> Self {
        Self {
            schema: Arc::new(Schema::default()),
            event: e.clone(),
            window: None,
            projects: Vec::new(),
            filters: None,
            maps: Vec::new(),
            group_by: Vec::new(),
            aggs: Vec::new(),
            distinct: false,
            distinct_join: None,
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct BpfJoin {
    pub l: Arc<Schema>,
    pub r: Arc<Schema>,
    pub fields: Vec<Field>,
}

pub struct PhysicalPlan {
    /// Physical plans for each event.
    pub event_plans: Vec<BpfPlan>,
}

impl PhysicalPlan {
    pub fn from_select(s: SelectStatement) -> Result<PhysicalPlan> {
        // Generate query name
        let query_name = format!(
            "select_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 5)
        );
        // Attempts to get event name from table
        if s.tables.len() != 1 {
            unimplemented!("Only one table selects are supported")
        }
        let e =
            get_event(&s.tables[0].name).context("Select table does not correspond to an event")?;

        // Construct BPF plan
        let mut bpf_plan = BpfPlan::new(&e);

        // Mark whether distinct
        bpf_plan.distinct = s.distinct;

        // Parse fields to project, and see which aggregations to use
        let mut project_fields = Vec::new();
        let mut output_fields = Vec::new();

        // Parse window
        if let Some(window) = s.window {
            match window.wt {
                nom_sql::WindowType::Time(ival, step) => {
                    if ival != step {
                        unimplemented!("non-tumbling windows not yet supported")
                    }
                    bpf_plan.window = Some(WindowType::Time(ival, step));
                    project_fields.push(e.get_arg("time").unwrap());
                }
                nom_sql::WindowType::Count(count, step) => {
                    if count != step {
                        unimplemented!("non-tumbling windows not yet supported")
                    }
                    bpf_plan.window = Some(WindowType::Count(count as usize, step as usize));
                }
            }
        }

        // Parse group by clause
        if let Some(gb) = s.group_by {
            // Get column names
            let cols = gb
                .columns
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>();
            // Get fields associated with columns
            let fields = e.get_args(&cols)?;
            // Add them to be projected *and* outputted
            fields.iter().for_each(|f| {
                if !project_fields.contains(f) {
                    project_fields.push(f.clone());
                }
            });
            fields.iter().for_each(|f| {
                if !output_fields.contains(f) {
                    output_fields.push(f.clone());
                }
            });
            // Mark them as fields to group by
            bpf_plan.group_by = fields;
            // fields.iter().map(|f| Field::from(f)).collect();
        }

        // Parse field selections and their aggregates
        for f_def in s.fields {
            match f_def {
                FieldDefinitionExpression::All => {
                    e.get_all_args()?.iter().for_each(|f| {
                        if !project_fields.contains(f) {
                            project_fields.push(f.clone());
                        }
                    });
                }
                FieldDefinitionExpression::AllInTable(_) => {
                    unimplemented!("cannot select from tables other than own event")
                }
                FieldDefinitionExpression::Col(c) => {
                    let (proj_f, out_f, op, d) = get_column(c, &e)?;
                    bpf_plan.distinct = bpf_plan.distinct || d;
                    if let Some(op) = op {
                        bpf_plan.aggs.push(op);
                    }
                    proj_f.into_iter().for_each(|f| {
                        if !project_fields.contains(&f) {
                            project_fields.push(f.clone());
                        }
                    });
                    out_f.into_iter().for_each(|f| {
                        if !output_fields.contains(&f) {
                            output_fields.push(f.clone());
                        }
                    });
                }
                _ => unimplemented!("field definition expressions not supported"),
                // FieldDefinitionExpression::Value(fve) => {
                //     match fve {
                //         Arithmetic(ae) => {
                //             // Make map operator from this
                //             bpf_plan
                //                 .maps
                //                 .push(Operator::Map(MapExpression::from(ae.clone())));
                //             // Extract values from columns
                //             for v in [ae.ari.left, ae.ari.right] {
                //                 if let ArithmeticBase::Column(c) = v {
                //                     let (proj_f, out_f, op, d) = get_column(c, &e)?;
                //                     bpf_plan.distinct = bpf_plan.distinct || d;
                //                     if let Some(op) = op {
                //                         // Maps shouldn't be operating on aggregates
                //                         unimplemented!("maps on aggregates not supported")
                //                         // bpf_plan.aggs.push(op);
                //                     }
                //                     proj_f.into_iter().for_each(|f| {
                //                         project_fields.insert(f._name.clone(), f);
                //                     });
                //                     out_f.into_iter().for_each(|f| {
                //                         output_fields.insert(f._name.clone(), f);
                //                     });
                //                 }
                //             }
                //         }
                //         Literal(_) => unimplemented!("literal selections not supported"),
                //     }
                // }
            };
        }
        // Parse where clause (i.e. filters)
        if let Some(ce) = s.where_clause {
            // Get all columns and associated fields
            get_contained_columns(&ce, &e)?.iter().for_each(|f| {
                if !project_fields.contains(f) {
                    project_fields.push(f.clone());
                }
            });
            // Create filter op out of it
            bpf_plan.filters = Some(Operator::Filter(ce));
        }

        let mut plan = PhysicalPlan {
            event_plans: Vec::new(),
        };

        // Parse join clause if it exists
        match s.join.len() {
            2.. => unimplemented!("only one join allowed"),
            1 => {
                let join = &s.join[0];
                // Only support joins (i.e. left joins)
                if !matches! { join.operator, JoinOperator::Join } {
                    unimplemented!("Join {} not supported", join.operator)
                }
                // Only support joins on another select statement for now
                if !matches! { join.right, JoinRightSide::NestedSelect(_, _)} {
                    unimplemented!("Join on {} not supported", join.right)
                }
                if let JoinRightSide::NestedSelect(select, _) = &join.right {
                    // Parse inside nested select
                    let join_bpf_plan = Self::from_select(*select.clone())?;
                    // TODO: migrate this out so it's not this garbage
                    let mut join_bpf_plan = join_bpf_plan.event_plans[0].clone();

                    // Get join condition
                    let join_fields = match &join.constraint {
                        JoinConstraint::On(_) => {
                            unimplemented!("Join filter {} not yet supported", &join.constraint)
                        }
                        JoinConstraint::Using(cols) => {
                            // Get column names
                            let cols = cols.iter().map(|c| c.name.as_str()).collect::<Vec<_>>();
                            // Get fields associated with columns
                            e.get_args(&cols)?
                                .iter()
                                .map(|f| Field::from(f))
                                .collect::<Vec<_>>()
                        }
                    };
                    bpf_plan.distinct_join = Some(BpfJoin {
                        l: bpf_plan.schema.clone(),
                        r: join_bpf_plan.schema.clone(),
                        fields: join_fields.clone(),
                    });
                    join_bpf_plan.distinct_join = Some(BpfJoin {
                        l: bpf_plan.schema.clone(),
                        r: join_bpf_plan.schema.clone(),
                        fields: join_fields,
                    });
                    plan.event_plans.push(join_bpf_plan);
                }
            }
            _ => (),
        }

        // Get fields to project
        bpf_plan.projects = project_fields.clone();
        // If output fields exist (i.e. an aggregation occurred), use those; otherwise,
        // copy project fields
        if output_fields.len() > 0 {
            bpf_plan.schema = Arc::new(Schema::new(
                Some(query_name),
                output_fields
                    .clone()
                    .into_iter()
                    .map(|f| Field::from(f))
                    .collect(),
            ));
        } else {
            bpf_plan.schema = Arc::new(Schema::new(
                Some(query_name),
                bpf_plan
                    .projects
                    .clone()
                    .iter()
                    .map(|f| Field::from(f))
                    .collect(),
            ));
        }

        plan.event_plans.push(bpf_plan);

        Ok(plan)
    }

    // Attempts to construct a physical plan given a logical plan.
    // pub fn new(plan: LogicalPlan) -> Result<PhysicalPlan> {
    //     // Walk through each of the logical plan's events.
    //     for (event_name, start) in plan.events {
    //         let mut ep = EventPlan::default();
    //         let mut bpf_op = true;

    //         // Get starting schema
    //         let schema = plan.op_graph[start].clone();
    //         let mut bpf_plan = BpfPlan::default();

    //         // Traverse through children
    //         let mut children = plan.op_graph.children(start);
    //         while let Some((op, next_schema)) =
    // children.walk_next(&plan.op_graph) {             // Update schema
    //             let schema = plan.op_graph[next_schema].clone();

    //             // Add operator to BPF plan
    //             let op = &plan.op_graph[op];
    //             match op {
    //                 Operator::Window(_) => todo!(),
    //                 Operator::Select(_) => todo!(),
    //                 Operator::Project(_) => todo!(),
    //                 Operator::Filter(_) => todo!(),
    //                 Operator::Map(_, _, _) => todo!(),
    //                 Operator::MapInPlace(_, _) => todo!(),
    //                 Operator::GroupBy(_) => todo!(),
    //                 Operator::Histogram(_) => todo!(),
    //                 Operator::Quantile(_) => todo!(),
    //                 Operator::Max(_) => todo!(),
    //                 Operator::Min(_) => todo!(),
    //                 Operator::Average(_) => todo!(),
    //                 Operator::Sum(_) => todo!(),
    //                 Operator::Count(_) => todo!(),
    //                 Operator::Join(_) => todo!(),
    //                 Operator::DistinctJoin(_) => todo!(),
    //             }

    //             children = plan.op_graph.children(next_schema);
    //         }
    //         /*
    //         TODO: figure out how to get schema
    //         TODO: walk through the tree, converting each operator into physical
    // operator         TODO: for now, put everything into bpf and reject ones
    // that can't         TODO: finally, output event plans
    //          */
    //     }
    //     // TODO: see if can compile query from physical plan into query handle
    //     todo!()
    // }
}

/// Gets the field associated with a column at an event, the name for the
/// aggregated field, and an optional aggregation / distinct marker
fn get_column(
    c: Column,
    e: &Arc<dyn Event>,
) -> Result<(Vec<types::Field>, Vec<types::Field>, Option<Operator>, bool)> {
    // See if this column involves an aggregation
    if let Some(func) = c.function {
        match *func {
            FunctionExpression::Avg(ref col, d) => {
                if let FunctionArgument::Column(col) = col {
                    // Assert that no nested function computations
                    if let Some(_) = col.function {
                        unimplemented!("nested aggs not supported")
                    }
                    // Add two fields: avg_{field}, and avg_{field}_count
                    let f_avg = types::Field::new(format!("avg_{}", &col.name), Type::U64);
                    // let f_count = types::Field::new(format!("avg_{}_count", &col.name),
                    // Type::U64);
                    return Ok((
                        vec![e.get_arg(&col.name)?],
                        vec![f_avg],
                        Some(Operator::Average(col.name.clone())),
                        d,
                    ));
                } else {
                    unimplemented!("case when not supported")
                }
            }
            FunctionExpression::Count(ref col, d) => {
                if let FunctionArgument::Column(col) = col {
                    // Assert that no nested function computations
                    if let Some(_) = col.function {
                        unimplemented!("nested aggs not supported")
                    }
                    // Create new field
                    return Ok((
                        vec![e.get_arg(&col.name)?],
                        vec![types::Field::new(format!("count_{}", &col.name), Type::U64)],
                        Some(Operator::Count(Some(col.name.clone()))),
                        d,
                    ));
                } else {
                    unimplemented!("case when not supported")
                }
            }
            FunctionExpression::CountStar => {
                // Update distinct value
                return Ok((
                    vec![],
                    vec![types::Field::new(format!("count_"), Type::U64)],
                    Some(Operator::Count(None)),
                    false,
                ));
            }
            FunctionExpression::Sum(ref col, d) => {
                if let FunctionArgument::Column(col) = col {
                    // Assert that no nested function computations
                    if let Some(_) = col.function {
                        unimplemented!("nested aggs not supported")
                    }
                    // Add new field
                    return Ok((
                        vec![e.get_arg(&col.name)?],
                        vec![types::Field::new(format!("sum_{}", &col.name), Type::U64)],
                        Some(Operator::Sum(col.name.clone())),
                        d,
                    ));
                } else {
                    unimplemented!("case when not supported")
                }
            }
            FunctionExpression::Max(ref col) => {
                if let FunctionArgument::Column(col) = col {
                    // Assert that no nested function computations
                    if let Some(_) = col.function {
                        unimplemented!("nested aggs not supported")
                    }
                    // Update distinct value
                    return Ok((
                        vec![e.get_arg(&col.name)?],
                        vec![types::Field::new(format!("max_{}", &col.name), Type::U64)],
                        Some(Operator::Max(col.name.clone())),
                        false,
                    ));
                } else {
                    unimplemented!("case when not supported")
                }
            }
            FunctionExpression::Min(ref col) => {
                if let FunctionArgument::Column(col) = col {
                    // Assert that no nested function computations
                    if let Some(_) = col.function {
                        unimplemented!("nested aggs not supported")
                    }
                    // Update distinct value
                    return Ok((
                        vec![e.get_arg(&col.name)?],
                        vec![types::Field::new(format!("min_{}", &col.name), Type::U64)],
                        Some(Operator::Min(col.name.clone())),
                        false,
                    ));
                } else {
                    unimplemented!("case when not supported")
                }
            }
            // TODO: add histogram to grammar
            FunctionExpression::GroupConcat(_, _) => unimplemented!("group concat not supported"),
            FunctionExpression::Generic(_, _) => unimplemented!("support generic function calls"),
        }
    } else {
        Ok((vec![e.get_arg(&c.name)?], vec![], None, false))
    }
}

/// Gets the filters from a condition expression.
/// TODO: parse deeper trees if possible
fn get_contained_columns(
    ce: &ConditionExpression,
    e: &Arc<dyn Event>,
) -> Result<Vec<types::Field>> {
    let mut res = Vec::new();
    match ce {
        ConditionExpression::ComparisonOp(ct) | ConditionExpression::LogicalOp(ct) => {
            let cols = ct.contained_columns();
            for col in cols {
                // Assert that no nested function computations
                if let Some(_) = col.function {
                    unimplemented!("nested aggs within filters not supported")
                }
                res.push(e.get_arg(&col.name)?);
            }
        }
        ConditionExpression::Base(ConditionBase::Field(ref col)) => {
            // Assert that no nested function computations
            if let Some(_) = col.function {
                unimplemented!("nested aggs within filters not supported")
            }
            res.push(e.get_arg(&col.name)?);
        }
        _ => unimplemented!("conditional expression {ce} not supported"),
    }
    Ok(res)
}
