// *** INCLUDES SECTION *** //
// #include "vmlinux.h" /* all kernel types */
// #include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
// #include <bpf/bpf_helpers.h> /* most used_helpers: SEC, __always_inline, etc */
// #include <bpf/bpf_tracing.h> /*  */

#include "common.bpf.h"
#include "math.bpf.h"
#include "hist.bpf.h"
#include "window.bpf.h"

// *** DEFINITIONS SECTION *** //

/// #define constants? TODO: probably move the constant/window stuff to a diff helper?

// Batching size and emit timeouts
#define BATCH_SIZE 256
#define EMIT_TOUT_MS 100


// For type information, see tracepoint information for mm_filemap_delete_from_page_cache.
// Actual order manually optimizes for padding, but I implemented a struct optimizer, so can just
// reuse.
// typedef struct query_simple {
// 	u64 time;
//   u64 pfn;
//   u64 i_ino;
//   u64 count;  // NOTE: from select; will need to analyze selects in query plan to find new emissions
//   u32 s_dev;
//   s32 pid;
//   s32 tgid;
//   char comm[TASK_COMM_LEN]; // pre-defined by vmlinux.h
//   s32 ns_pid; // not rly useful but 🤷 for sake of demonstration
// } query_simple_t;  // __attribute__((packed));
// TODO: benchmark packed impact on performance hit.

// Ringmap to communicate with userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BATCH_SIZE * sizeof(query_simple_t)); // this is in bytes, so get actual size
} ring_buf_8uf3Z SEC(".maps");

// *** GLOBALS SECTION *** //

// Global window state representation
window_t window = {0};

// total event count (user-defined state!)
u64 count = 0;

hist_t hist = {
    .buckets = {{0, 5, 0}, {5, 10, 0}, {10, 15, 0}, {15, 20, 0}},
    .count = 0,
};

// TODO: should prob have another section for flags like these
const volatile s32 target_pid = 0;

// *** CODE SECTION *** //
// TODO: see how tracepoint types are defined. Looks like it's trace_event_raw_XXX, but e.g. it's
// different for syscalls.
SEC("tracepoint/filemap/mm_filemap_add_to_page_cache")
u32 bpf_query_simple(struct trace_event_raw_mm_filemap_op_page_cache * ctx) {
	bpf_printk("got event\n");

  // Preliminaries
  query_simple_t q = {};
  s64 ret = 0;

  // PROJECT: get all baseline attributes
  q.time = bpf_ktime_get_ns();
  q.pfn = ctx->pfn;
  q.i_ino = ctx->i_ino;
  q.s_dev = ctx->s_dev;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  q.pid = pid_tgid >> 32;
  q.tgid = (u32)pid_tgid;
  char comm[TASK_COMM_LEN];
  ret = bpf_get_current_comm(&q.comm, sizeof(q.comm));
  if (ret < 0) {
    bpf_printk("got error in getting comm: %ld", ret);
  }

  // SELECT: for each new arg, compute its value
  // - for user-defined state, operate on that and return its value
  count += 1;
  q.count = count;

  // - for other stuff (i.e. using source args -> new args), use bpf helpers / regular
  // computation
  // TODO: figure out how to represent bpf helper funcs; probably some parsing of
  // include/uapi/linux/bpf.h?
  struct bpf_pidns_info nsd;
  ret = bpf_get_ns_current_pid_tgid(ctx->s_dev, ctx->i_ino, &nsd, sizeof(nsd));
  if (ret != 0) {
    bpf_printk("got error in getting ns_pid: %ld", ret);
  }
  q.ns_pid = nsd.pid;

  // FILTER: p simple if-cond I think
  if (target_pid != 0 && q.pid != target_pid) {
    bpf_printk("event from pid %d filtered (target pid: %d)", q.pid, target_pid);
    return 0;
  }

  // MAP: apply pre-defined set of arithmetic/string processing functions
  q.time /= MS_TO_NS;


  // Insert into window
  window_add(&window, q);
  hist_insert(&hist, q.pfn);
  hist_quantile(&hist, 99);

  // AGGREGATE: TODO: figure out how to do in kernel space without wasting memory...

  return 0;
}


// *** LICENSE *** //
char LICENSE[] SEC("license") = "Dual BSD/GPL";
