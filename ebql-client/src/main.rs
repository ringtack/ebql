use clap::Parser;
use ebql::{
    exec::executor::Executor,
    query::{bpf_ops::compiler::QueryCompiler, parser::parse_query, physical_plan::PhysicalPlan},
};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    query: String,
}

fn main() {
    log::set_max_level(log::LevelFilter::Info);
    env_logger::builder()
        .filter(None, log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    let s = parse_query(args.query).unwrap();
    let physical_plan = PhysicalPlan::from_select(s).unwrap();
    let bpf_plan = &physical_plan.event_plans[0];

    log::info!("Schema: {}", bpf_plan.schema);

    let mut qc = QueryCompiler {};
    let obj = qc.compile_bpf_ops(bpf_plan).unwrap();

    let exec = Executor::new(obj).unwrap();
    let rx = exec.prog_streams.get(&bpf_plan.schema.name).unwrap();
    for rb in rx {
        println!("{rb}")
    }
}

/*
   let event = get_event("syscalls/sys_enter_pread64").unwrap();
   let schema = Schema::new(
       Some(String::from("simple_1")),
       vec![
           Field {
               name: String::from("cpu"),
               data_type: DataType::UInt64,
           },
           Field {
               name: String::from("count_cpu"),
               data_type: DataType::UInt64,
           },
           Field {
               name: String::from("avg_count"),
               data_type: DataType::UInt64,
           },
           Field {
               name: String::from("avg_count_count"),
               data_type: DataType::UInt64,
           },
       ]
       .into(),
   );
   let window = WindowType::Time(Duration::from_secs(1), Duration::from_secs(1));
   let projects = vec![
       types::Field::new(String::from("time"), Type::U64),
       types::Field::new(String::from("cpu"), Type::U64),
       types::Field::new_with_off(String::from("count"), Type::U64, String::from("args"), 2),
       types::Field::new(String::from("pid"), Type::U64),
   ];
   let filter = Operator::Filter(ConditionExpression::ComparisonOp(ConditionTree {
       operator: nom_sql::Operator::Equal,
       left: Box::new(ConditionExpression::Base(ConditionBase::Field(Column {
           name: String::from("pid"),
           alias: None,
           table: None,
           function: None,
       }))),
       right: Box::new(ConditionExpression::Base(ConditionBase::Literal(
           Literal::UnsignedInteger(10000),
       ))),
   }));
   let group_by = vec![types::Field::new(String::from("cpu"), Type::U64)];

   let aggs = vec![
       Operator::Count(Some(String::from("cpu"))),
       Operator::Average(String::from("count")),
   ];

   let bpf_plan = BpfPlan {
       schema: Arc::new(schema),
       event,
       window: Some(window),
       projects,
       // filters: Some(filter),
       filters: None,
       maps: vec![],
       group_by,
       aggs,
       distinct: false,
       distinct_join: None,
   };

*/
