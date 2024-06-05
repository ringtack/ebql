use std::{env, ffi::OsString, fs, io, path::PathBuf};

use anyhow::{anyhow, Result};
use handlebars::Handlebars;
use nom_sql::{ConditionBase, ConditionExpression, Literal};
use rand::distributions::{Alphanumeric, DistString};

use super::MAX_MEM_BYTES;
use crate::{
    events::Event,
    map::RingBuf,
    object::Object,
    prog_builder::{BpfCodeBuilder, Expr},
    query::{
        bpf_ops::{agg::BpfAggregateTemplate, hist::BpfHistogramTemplate, window::BpfWindowType},
        operators::{Operator, WindowType},
        physical_plan::BpfPlan,
    },
    types::{Field, Type},
};

/// Query compiler into an actual BPF representation.
pub struct QueryCompiler {
    // TODO: add fields. for shared synopses, might want to store compiled query programs internally
    // to optimize future compilations.
}

impl QueryCompiler {
    pub fn compile_bpf_ops(&mut self, plan: &BpfPlan) -> Result<Object> {
        // Create code builder and template engine
        let mut cb = BpfCodeBuilder::new(
            plan.schema.name.clone(),
            format!(
                "{}/{}",
                plan.event.program_type().section_name(),
                plan.event.name()
            ),
        );
        let mut handlebars = Handlebars::new();

        // First, generate window definition
        match &plan.window {
            Some(wt) => {
                let wt = BpfWindowType::try_from(wt)?;
                // For windows, get external header file
                let tmpl = wt.get_tmpl(plan.schema.name.clone(), !plan.aggs.is_empty());
                // Render template into actual code
                handlebars.register_template_file(&tmpl.name, tmpl.tmpl_path)?;
                let text = handlebars.render(&tmpl.name, &tmpl.ctx)?;
                // Register rendered template into code builder
                cb.add_external_includes(&tmpl.name, text);
            }
            None => {
                return Err(anyhow!(
                    "Did not get window op for query {}",
                    plan.schema.name
                ))
            }
        }

        // Then, convert aggregates and joins into headers
        let mut agg_tmpl = BpfAggregateTemplate::new(plan.schema.name.clone(), &plan.group_by);
        for op in &plan.aggs {
            // Get template, then render into code
            match op {
                Operator::Histogram(buckets) => {
                    let tmpl = BpfHistogramTemplate::get_tmpl(buckets);
                    handlebars.register_template_file(&tmpl.name, tmpl.tmpl_path)?;
                    let text = handlebars.render(&tmpl.name, &tmpl.ctx)?;
                    // Register into code builder
                    cb.add_external_includes(&tmpl.name, text);
                }
                Operator::Max(_field)
                | Operator::Min(_field)
                | Operator::Average(_field)
                | Operator::Sum(_field) => {
                    agg_tmpl.ctx.update(op)?;
                }
                Operator::Count(_) => {
                    agg_tmpl.ctx.update(op)?;
                }
                // Operator::Count(None) => unimplemented!("TODO: implement count star"),
                _ => (),
            };
        }
        handlebars.register_template_file(&agg_tmpl.name, agg_tmpl.tmpl_path)?;
        let text = handlebars.render(&agg_tmpl.name, &agg_tmpl.ctx)?;
        cb.add_external_includes(&agg_tmpl.name, text);

        // TODO: handle joins
        if let Some(dj) = &plan.distinct_join {
            unimplemented!("TODO: implement join")
        }

        // Convert schema into bpf struct
        let bpf_struct = plan.schema.clone().to_bpf_struct(&plan.event)?;
        let struct_size = bpf_struct.sz;

        // Then, define ring buf from schema:
        let rb = RingBuf {
            name: format!(
                "ring_buf_{}",
                Alphanumeric.sample_string(&mut rand::thread_rng(), 5)
            ),
            s_repr: bpf_struct.clone(),
            max_entries: get_max_entries(&plan.window.as_ref().unwrap(), struct_size),
        };

        let cb = cb.write_ring_buffer(&rb);

        log::info!("RB schema: {}", rb.s_repr.schema);

        // Then, build program from operators (TODO: handle join after i get working)
        let args = vec![Expr::new(
            "ctx".into(),
            Type::Pointer(Box::new(Type::Struct(plan.event.ctx(), None))),
        )];
        let mut cb = cb.start_function(&args);

        // Project necessary values
        for f in &plan.projects {
            cb.write_field(f, None);
        }
        // let mut args = vec!["\"%d, %d, %d\""];
        // args.extend(plan.projects.iter().map(|f| f._name.as_str()));
        cb.write_func_call("DEBUG", &["\"Got event\""]);

        // Implement filter
        if let Some(filter) = &plan.filters {
            if let Operator::Filter(ce) = filter {
                let cond = ce_to_cond(&ce);
                cb.write_if(&cond);
                let filtered_str = vec!["\"Event did not match filter; dropping...\""];
                cb.write_func_call("INFO", &filtered_str);
                cb.write_return("1");
                cb.close_if();
            } else {
                return Err(anyhow!("got non-filter op {filter} in filters"));
            }
        }

        // Implement maps
        // TODO: finish this
        if plan.maps.len() > 0 {
            unimplemented!("maps not yet supported")
        }

        // Execute aggs if they exist; otherwise, execute join; otherwise, make struct
        // and add to window
        if plan.aggs.len() > 0 {
            // First, add to window and see if need to tumble
            let mut window_args = vec![];
            if let Some(WindowType::Time(_, _)) = plan.window {
                window_args.push("time");
            }
            cb.write_var_initialization(
                &Field::new(String::from("tumble"), Type::Bool),
                &format!("window_add({})", window_args.join(", ")),
            );

            // Check if we need to tumble
            cb.write_if("tumble");

            // Within the if, a tumble is required, so allocate space in the ringbuf
            let (agg_name, field_name) = match &plan.aggs[0] {
                Operator::Max(s) => ("max", s.as_str()),
                Operator::Min(s) => ("min", s.as_str()),
                Operator::Average(s) => ("avg", s.as_str()),
                Operator::Sum(s) => ("sum", s.as_str()),
                Operator::Count(Some(s)) => ("count", s.as_str()),
                Operator::Count(None) => ("count", ""),
                _ => {
                    return Err(anyhow!(
                        "First aggregation {} shuold be one of implemented aggs",
                        plan.aggs[0]
                    ))
                }
            };
            // Get the number of unique group bys in all aggs; just one agg should be
            // sufficient
            cb.write_var_initialization(
                &Field::new(String::from("n_results"), Type::U64),
                &format!("count_{}_{}_{}()", agg_name, field_name, &plan.schema.name),
            );
            // Appease verifier
            cb.write_if(&format!("n_results >= {}", &rb.max_entries));
            cb.write_func_call(
                "WARN",
                &["\"Got too many results; truncating to max rb entries...\""],
            );
            cb.write_var_assignment("n_results", &format!("{}", &rb.max_entries));
            cb.close_if();

            // Only run if we actually got results
            cb.write_if("n_results > 0");

            // Reserve rb space
            cb.write_var_initialization(
                &Field::new(
                    String::from("buf"),
                    Type::Pointer(Box::new(Type::Struct(
                        format!("{}_t", &plan.schema.name),
                        None,
                    ))),
                ),
                &format!(
                    "bpf_ringbuf_reserve(&{}, n_results * sizeof({}_t), 0)",
                    &rb.name, &plan.schema.name
                ),
            );

            // Bounds check to appease verifier
            cb.write_if("!buf");
            cb.write_func_call("ERROR", &["\"Failed to allocate from ring buffer\""]);
            cb.write_return("1");
            cb.close_if();

            // Iterate over aggs and compute result
            for agg in &plan.aggs {
                match agg {
                    Operator::Max(s) => {
                        let func = format!("get_max_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &["buf", "n_results"]);
                    }
                    Operator::Min(s) => {
                        let func = format!("get_min_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &["buf", "n_results"]);
                    }
                    Operator::Average(s) => {
                        let func = format!("get_avg_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &["buf", "n_results"]);
                    }
                    Operator::Sum(s) => {
                        let func = format!("get_sum_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &["buf", "n_results"]);
                    }
                    Operator::Count(Some(s)) => {
                        let func = format!("get_count_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &["buf", "n_results"]);
                    }
                    Operator::Count(None) => {
                        let func = format!("get_count__{}", &plan.schema.name);
                        cb.write_func_call(&func, &["buf", "n_results"]);
                    }
                    _ => unimplemented!("tumble agg for {agg} not implemented"),
                }
            }

            // Submit to ringbuf
            cb.write_func_call("bpf_ringbuf_submit", &["buf", "0"]);

            cb.close_if();

            // Tumble aggregations
            for agg in &plan.aggs {
                match agg {
                    Operator::Histogram(_) => unimplemented!("need to add histogram to nom-sql"),
                    Operator::Quantile(_) => unimplemented!("need to add histogram to nom-sql"),
                    Operator::Max(s) => {
                        let func = format!("tumble_max_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &[]);
                    }
                    Operator::Min(s) => {
                        let func = format!("tumble_min_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &[]);
                    }
                    Operator::Average(s) => {
                        let func = format!("tumble_avg_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &[]);
                    }
                    Operator::Sum(s) => {
                        let func = format!("tumble_sum_{}_{}", s, &plan.schema.name);
                        cb.write_func_call(&func, &[]);
                    }
                    Operator::Count(s) => {
                        match s {
                            Some(s) => {
                                let func = format!("tumble_count_{}_{}", s, &plan.schema.name);
                                cb.write_func_call(&func, &[]);
                            }
                            None => {
                                let func = format!("tumble_count__{}", &plan.schema.name);
                                cb.write_func_call(&func, &[]);
                            }
                        }
                    }
                    _ => return Err(anyhow!("Operator {agg} not an aggregate!")),
                }
            }

            // Tumble window
            cb.write_func_call("window_tumble", &window_args);
            cb.close_if();

            // After ifs are closed (i.e. after we potentially tumble), insert into aggs
            let gb = if plan.group_by.len() > 0 {
                format!(
                    "(group_by_{}_t){{{}}}",
                    &plan.schema.name,
                    plan.group_by
                        .iter()
                        .map(|f| f._name.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            } else {
                // If no GB, use dummy var
                unimplemented!("non-grouped aggs not yet supported")
            };
            for agg in &plan.aggs {
                match agg {
                    Operator::GroupBy(_) => unimplemented!("shouldn't have any group bys"),
                    Operator::Histogram(_) => unimplemented!("need to add histogram to nom-sql"),
                    Operator::Quantile(_) => unimplemented!("need to add histogram to nom-sql"),
                    Operator::Max(s) => {
                        let func = format!("insert_max_{}_{}", s, &plan.schema.name);
                        let args = vec![gb.as_str(), s.as_str()];
                        cb.write_func_call(&func, &args);
                    }
                    Operator::Min(s) => {
                        let func = format!("insert_min_{}_{}", s, &plan.schema.name);
                        let args = vec![gb.as_str(), s.as_str()];
                        cb.write_func_call(&func, &args);
                    }
                    Operator::Average(s) => {
                        let func = format!("insert_avg_{}_{}", s, &plan.schema.name);
                        let args = vec![gb.as_str(), s.as_str()];
                        cb.write_func_call(&func, &args);
                    }
                    Operator::Sum(s) => {
                        let func = format!("insert_sum_{}_{}", s, &plan.schema.name);
                        let args = vec![gb.as_str(), s.as_str()];
                        cb.write_func_call(&func, &args);
                    }
                    Operator::Count(s) => {
                        match s {
                            Some(s) => {
                                let func = format!("insert_count_{}_{}", s, &plan.schema.name);
                                let args = vec![gb.as_str(), "1"];
                                cb.write_func_call(&func, &args);
                            }
                            None => {
                                let func = format!("insert_count__{}", &plan.schema.name);
                                let args = vec![gb.as_str(), "1"];
                                cb.write_func_call(&func, &args);
                            }
                        }
                    }
                    _ => return Err(anyhow!("Operator {agg} not an aggregate!")),
                }
            }
        } else if let Some(dj) = &plan.distinct_join {
            unimplemented!("distinct joins not yet supported")
        } else {
            // Add to window
            let window_arg = format!(
                "({}_t){{{}}}",
                &plan.schema.name,
                plan.projects
                    .iter()
                    .map(|f| f._name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            cb.write_var_initialization(
                &Field::new(String::from("tumble"), Type::Bool),
                &format!("window_add({})", window_arg),
            );

            // If tumble, copy over
            cb.write_if("tumble");

            cb.write_var_initialization(
                &Field::new(String::from("n_results"), Type::U64),
                "get_size()",
            );

            // Only proceed if we actually have results
            // cb.write_if("n_results > 0");

            // Appease verifier
            cb.write_if(&format!("n_results >= {}", &rb.max_entries));
            cb.write_func_call(
                "WARN",
                &["\"Got too many results; truncating to max rb entries...\""],
            );
            cb.write_var_assignment("n_results", &format!("{}", &rb.max_entries));
            cb.close_if();

            let n_bytes = format!("n_results * sizeof({}_t)", &plan.schema.name);
            // Reserve space in ringbuf
            cb.write_var_initialization(
                &Field::new(
                    String::from("buf"),
                    Type::Pointer(Box::new(Type::Struct(
                        format!("{}_t", &plan.schema.name),
                        None,
                    ))),
                ),
                &format!("bpf_ringbuf_reserve(&{}, {}, 0)", &rb.name, n_bytes),
            );

            // Bounds check to appease verifier
            cb.write_if("!buf");
            cb.write_func_call("ERROR", &["\"Failed to allocate from ring buffer\""]);
            cb.write_return("1");
            cb.close_if();

            // Copy over from window
            cb.write_func_call("bpf_probe_read_kernel", &["buf", n_bytes.as_str(), "w.buf"]);

            // Submit
            cb.write_func_call("bpf_ringbuf_submit", &["buf", "0"]);

            // cb.close_if();

            // Afterwards, tumble window
            if matches! {&plan.window, Some(WindowType::Time(_, _))} {
                cb.write_func_call("window_tumble", &[&window_arg]);
            } else {
                cb.write_func_call("window_tumble", &[]);
            }
            cb.close_if();
        }

        cb.write_return("0");
        let cb = cb.close();

        // Build into object
        let root = get_project_root().unwrap();
        let out_dir = get_out_dir(&root).unwrap();
        // Clear directory TODO: change this later
        let _ = fs::remove_dir_all(&out_dir);
        create_dir_if_not_exists(&out_dir).unwrap();

        let br = cb.build(&out_dir)?;

        let obj = Object::load(&plan.schema.name, vec![br], None)?;

        Ok(obj)
    }
}

fn get_max_entries(wt: &WindowType, s_size: usize) -> u64 {
    match wt {
        WindowType::Time(_, _) => MAX_MEM_BYTES / (s_size as u64),
        WindowType::Count(count, _) => {
            if (count * s_size) as u64 > MAX_MEM_BYTES {
                MAX_MEM_BYTES / (s_size as u64)
            } else {
                *count as u64
            }
        }
        WindowType::Session(_) => todo!(),
    }
}

/// Convert conditional expression into if cond statement. Here, we do the
/// opposite, since if we want this filter to be satisfied, we should filter out
/// all things that don't satisfy the filter.
fn ce_to_cond(ce: &ConditionExpression) -> String {
    let str = match ce {
        ConditionExpression::Base(cb) => {
            match cb {
                ConditionBase::Field(col) => col.name.clone(),
                ConditionBase::Literal(l) => {
                    match l {
                        Literal::Integer(_) | Literal::UnsignedInteger(_) => l.to_string(),
                        _ => unimplemented!("Literal {} not supported", l.to_string()),
                    }
                }
                _ => unimplemented!("condition base {cb} not supported"),
            }
        }
        ConditionExpression::ComparisonOp(ct) => {
            match ct.operator {
                nom_sql::Operator::Equal => {
                    format!("({}) != ({})", ce_to_cond(&ct.left), ce_to_cond(&ct.right))
                }
                nom_sql::Operator::NotEqual => {
                    format!("({}) == ({})", ce_to_cond(&ct.left), ce_to_cond(&ct.right))
                }
                nom_sql::Operator::Greater => {
                    format!("({}) <= ({})", ce_to_cond(&ct.left), ce_to_cond(&ct.right))
                }
                nom_sql::Operator::GreaterOrEqual => {
                    format!("({}) < ({})", ce_to_cond(&ct.left), ce_to_cond(&ct.right))
                }
                nom_sql::Operator::Less => {
                    format!("({}) >= ({})", ce_to_cond(&ct.left), ce_to_cond(&ct.right))
                }
                nom_sql::Operator::LessOrEqual => {
                    format!("({}) > ({})", ce_to_cond(&ct.left), ce_to_cond(&ct.right))
                }
                _ => {
                    unimplemented!(
                        "conditional operator {} not supported for comparisons",
                        ct.operator
                    )
                }
            }
        }
        ConditionExpression::LogicalOp(ct) => {
            match ct.operator {
                nom_sql::Operator::And => {
                    format!(
                        "!({}) || !({})",
                        ce_to_cond(&ct.left),
                        ce_to_cond(&ct.right)
                    )
                }
                nom_sql::Operator::Or => {
                    format!(
                        "!({}) && !({})",
                        ce_to_cond(&ct.left),
                        ce_to_cond(&ct.right)
                    )
                }
                _ => {
                    unimplemented!(
                        "conditional operator {} not supported for logical operators",
                        ct.operator
                    )
                }
            }
        }
        _ => unimplemented!("condition expression {ce} not supported"),
    };

    str
}

/*
// First, get all necessary includes and header information
for op in plan {
    match op {
        Operator::Window(wt) => {
            let wt = BpfWindowType::try_from(wt)?;
            // For windows, get external header file
            let tmpl = wt.get_tmpl(name.clone());
            // Render template into actual code
            handlebars.register_template_file(&tmpl.name, tmpl.tmpl_path)?;
            let text = handlebars.render(&tmpl.name, &tmpl.ctx)?;
            // Register rendered template into code builder
            cb.add_external_includes(&tmpl.name, text);
        }
        Operator::Histogram(buckets) => {
            // Get template, then render into code
            let tmpl = BpfHistogramTemplate::get_tmpl(buckets);
            handlebars.register_template_file(&tmpl.name, tmpl.tmpl_path)?;
            let text = handlebars.render(&tmpl.name, &tmpl.ctx)?;
            // Register into code builder
            cb.add_external_includes(&tmpl.name, text);
        }
        Operator::Max(_)
        | Operator::Min(_)
        | Operator::Average(_)
        | Operator::Sum(_)
        | Operator::Count(_) => todo!(),
        Operator::DistinctJoin(_) => todo!(),
        Operator::Join(_) => todo!(),
        _ => (),
    }
}

// TODO: define ring buf before starting function

// Then, build program from operators
let ctx = e.ctx();
let args = vec![Expr::new(
    "ctx".into(),
    Type::Pointer(Box::new(Type::Struct(ctx, None))),
)];
let cb = cb.start_function(&args);
// TODO: these should be sorted already by the logical plan optimizer: filters
// -> projects -> maps -> aggs

// TODO: but I should also group myself... but also wait in the simplest form
// there should only be either an aggregation (ig we could compute multiple aggs
// on diff things), and/or a distinct -> join
//
// steps:
// - add to window
// - if no tumble: insert into aggregations and join synopsis
// - if tumble: emit aggregations and joins

for op in ops {
    match op {
        Operator::Window(_) => todo!(),
        Operator::Select(_) => todo!(),
        Operator::Project(_) => todo!(),
        Operator::Filter(_, _) => todo!(),
        Operator::Map(_, _, _) => todo!(),
        Operator::MapInPlace(_, _) => todo!(),
        Operator::GroupBy(_) => todo!(),
        Operator::Histogram(_) => todo!(),
        Operator::Quantile(_) => todo!(),
        Operator::Max(_) => todo!(),
        Operator::Min(_) => todo!(),
        Operator::Average(_) => todo!(),
        Operator::Sum(_) => todo!(),
        Operator::Count => todo!(),
        Operator::Join(_) => todo!(),
        Operator::DistinctJoin(_) => todo!(),
    }
}

let cb = cb.close();
todo!()
*/

fn get_project_root() -> io::Result<PathBuf> {
    let path = env::current_dir()?;
    let mut path_ancestors = path.as_path().ancestors();

    while let Some(p) = path_ancestors.next() {
        let has_cargo = std::fs::read_dir(p)?
            .into_iter()
            .any(|p| p.unwrap().file_name() == OsString::from("Cargo.lock"));
        if has_cargo {
            return Ok(PathBuf::from(p));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Ran out of places to find Cargo.toml",
    ))
}

fn get_out_dir(base: &PathBuf) -> Option<PathBuf> {
    // First we get the arguments for the rustc invocation
    let mut args = std::env::args();

    // Then we loop through them all, and find the value of "out-dir"
    while let Some(arg) = args.next() {
        if arg.contains("target") {
            let mut path = base.clone();
            path.push(PathBuf::from(arg));
            path.pop();
            path.push("tmp_build");
            return Some(path);
        }
    }
    None
}

// Creates directory if not exists
fn create_dir_if_not_exists(dir: &PathBuf) -> io::Result<()> {
    if let Ok(metadata) = fs::metadata(dir) {
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Directory {} already exists, but is not a directory",
                    dir.display()
                ),
            ));
        }
        Ok(())
    } else {
        fs::create_dir(dir)
    }
}
