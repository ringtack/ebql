mod test {
    include!(concat!(env!("OUT_DIR"), "/test.skel.rs"));
}

use core::str;

use ebql_prototype::{
    bpf_gen::{BpfCompiler, StructRepr},
    bpf_select::BpfSelect,
    bpf_types::{Field, TracepointEvent, Type},
};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder,
};
use test::*;

fn main() {
    /*
    Suppose we want the following query:

    SELECT ktime (8), pfn (8), i_ino (8), pid (4), tgid (4), comm,
      pid, tgid AS get_ns_current_pid_tgid(dev, ino, ...)
      WHERE pid = target_pid
        AND

    let add = QueryBuilder::new()
      .Event("mm_filemap_add_to_page_cache")
      .Window(Count(256, 1))
      .Project(time, pfn, i_ino, s_dev, pid, tgid, comm)
      .Select( // TODO: better operator name? What's the standard? LINQ does Select
        [], // source args
        [count], // new args
        |args| -> { count = global.count++ } // TODO: figure out how to handle global args?
      )
      .Filter(pid == target_pid)
      .Map([
        { [time], [time], Div(time, 1_000_000), }, // map functions; if out same, keep name
      ])
      .Aggregate(GroupBy, i_ino) // TODO: for group bys, might need to emit to user-space? maintain set and emit in batches, or just defer to user space; could maintain a map of maps for grouping results, pre-created and hashed or smth, but might duplicate computation

      ... OR ...

      .Aggregate(Count, i_ino) // TODO: For aggregates like count/mean/etc., no need to project since doesn't make sense? so emit after this

      ... OR ...

      .Aggregate(Distinct, pfn); for min/max/distinct, could emit projected vals // TODO: distinct not an agg, change maybe? also prioritize latest updates I think
      .Map([
        { [comm], [commLen], comm.len() },
      ])
      .Filter(commLen >= 5)
      .Aggregate(Min, commLen)
      .Build(BatchSize: 256) // collect in output ringbuf or smth, check how franco batched


    If we wanted to join adds and deletes by pfn, don't build above and instead:
    - also for me: probably remove the filters

    let del = QueryBuilder::new()
      .Event("mm_filemap_delete_from_page_cache")
      .Window(Count(256, 1))
      .Project(time, pfn, i_ino, s_dev, pid, tgid, comm)
      .Filter(pid == target_pid)
      .Map([
        { [time], [time], Div(time, 1_000_000), }, // map functions; if out same, keep name
      ])
      .Aggregate(Distinct, pfn);
      .Map([
        { [comm], [commLen], comm.len() },
      ])
      .Filter(commLen >= 5)

    let join = QueryBuilder::new()
        .Join(
          add,
          del,
          [pfn] // join clauses, where equality checked for everything in list
        ) // output shares join clauses, renames other clauses
        .Build(BatchSize: 256) // TODO: maybe use step size as batch??

     */

    // Define struct representation and event handler
    let s_repr = StructRepr {
        fields: vec![],
        name: "test_t".into(),
    };

    let process_event = create_event_handler(s_repr);

    // Initialize BPF skeleton program
    let skel_builder = TestSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let mut skel = open_skel.load().unwrap();

    // Create ring buf handler
    let maps = skel.maps();
    let mut builder = RingBufferBuilder::new();
    builder.add(&maps.ring_buf_8uf3Z(), process_event).unwrap();
    let rb = builder.build().unwrap();

    // Attach program to event
    let link = skel.progs_mut().bpf_select_ckJsb().attach().unwrap();

    // Continuously poll until stopped
    while rb.poll(Duration::MAX).is_ok() {}
}

pub fn create_event_handler(s_repr: StructRepr) -> impl FnMut(&[u8]) -> i32 {
    let s_repr = s_repr.clone();
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
                        std::mem::transmute::<[u8; 2], u16>(buf[pos..pos + 2].try_into().unwrap())
                    };
                    print!("{}, ", val);
                }
                Type::U32 => {
                    let val = unsafe {
                        std::mem::transmute::<[u8; 4], u32>(buf[pos..pos + 4].try_into().unwrap())
                    };
                    print!("{}, ", val);
                }
                Type::U64 => {
                    let val = unsafe {
                        std::mem::transmute::<[u8; 8], u64>(buf[pos..pos + 8].try_into().unwrap())
                    };
                    print!("{}, ", val);
                }
                Type::S8 => {}
                Type::S16 => {
                    let val = unsafe {
                        std::mem::transmute::<[u8; 2], i16>(buf[pos..pos + 2].try_into().unwrap())
                    };
                    print!("{}, ", val);
                }
                Type::S32 => {
                    let val = unsafe {
                        std::mem::transmute::<[u8; 4], i32>(buf[pos..pos + 4].try_into().unwrap())
                    };
                    print!("{}, ", val);
                }
                Type::S64 => {
                    let val = unsafe {
                        std::mem::transmute::<[u8; 8], i64>(buf[pos..pos + 8].try_into().unwrap())
                    };
                    print!("{}, ", val);
                }
                Type::String(len) => {
                    let s = match str::from_utf8(&buf[pos..pos + len]) {
                        Ok(v) => v,
                        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                    };
                    print!("{}, ", s);
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
