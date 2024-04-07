// *** INCLUDES SECTION *** //
// #include "vmlinux.h" /* all kernel types */
// #include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
// #include <bpf/bpf_helpers.h> /* most used_helpers: SEC, __always_inline, etc */
// #include <bpf/bpf_tracing.h> /*  */

#include "common.bpf.h"
#include "math.bpf.h"
#include "simple_1.bpf.h"

#include "window.bpf.h"
#include "hist.bpf.h"
#include "avg.bpf.h"
#include "distinct_simple_1.bpf.h"

// #include "join.bpf.h"
#include "distinct_join.bpf.h"

// *** DEFINITIONS SECTION *** //

/// #define constants? TODO: probably move the constant/window stuff to a diff helper?

// Batching size and emit timeouts
#define BATCH_SIZE 256
#define EMIT_TOUT_MS 100

// Ringmap to communicate with userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RESULT_SIZE * sizeof(simple_1_simple_2_t));
} ring_buf_8uf3Z SEC(".maps");

// *** GLOBALS SECTION *** //

// total event count (user-defined state!)
u64 count = 0;

// TODO: should prob have another section for flags like these
const volatile s32 target_pid = 0;

// *** CODE SECTION *** //

/**
 * Callback on window flushes. Executed only for individual processing.
 */
static s64 __window_flush_callback_simple_1(u32 i, window_t *w) {
  // Stop if i >= w->size
  if (i >= w->size) {
    return 1;
  }
  // Get actual offset; although mod isn't necessary, do to appease verifier
  i = (i + w->tail) % WINDOW_SIZE;

  // Apply processing on w->buf[i]

  // Joins:

  // Delete from its bucket
  join_delete_bucket_simple_1(w->buf[i]);
  // signal to user-space to delete these records from join result
  // TODO: make join deleted result using ts1, ts2

  // Aggregations:

  // delete from histogram
  hist_delete(&hist, w->buf[i].pfn);

  // Count / mean: update
  // Distinct: we have distinct record the latest seen value. If this value == last seen distinct
  // value, then no other distinct values seen, so remove

  return 0;
}

// TODO: see how tracepoint types are defined. Looks like it's trace_event_raw_XXX, but e.g. it's
// different for syscalls.
SEC("tracepoint/filemap/mm_filemap_add_to_page_cache")
u32 bpf_simple_1(struct trace_event_raw_mm_filemap_op_page_cache * ctx) {
	INFO("got event");

  // Preliminaries
  simple_1_t q = {};
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
    return 1;
  }

  // SELECT: for each new arg, compute its value
  // - for user-defined state, operate on that and return its value
  count += 1;
  q.count = count;

  // - for other stuff (i.e. using source args -> new args), use bpf helpers / regular
  // computation
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

  // Add element to window
  ret = window_add(q);
  if (ret < 0) {
    ERROR("failed to add to window (%ld)", ret);
    return 1;
  }

  // {{ if window.is_tumbling }}
  // TODO: benchmark individual vs. batch processing (batch prob faster since cache locality, but
  // might incur high tail latencies)
  // If individual processing:

  // If ret == 0, then element went to window, so update current aggregations
  if (ret == 0) {
    // Aggregations:

    // Insert into histogram
    hist_insert(&hist, q.pfn);

    // Update average
    avg_insert(q.pfn, q.time);

    // Update distinct
    distinct_insert_simple_1(q);

    // Joins:
    // Insert new element into bucket
    // join_insert_bucket_simple_1(q);
    // Compute new join results with other query
    // join_elt_simple_2(&q);
  } else if (ret == 1) {
    // Otherwise, if ret == 1, then element went to next buffer, so update next aggregations

    // Aggregations:

    // Insert into next histogram
    hist_insert(&hist_next, q.pfn);

    // Update average
    avg_insert_next(q.pfn, q.time);

    // Update distinct
    // Note: since distinct joins build on this, it suffices for that too
    distinct_insert_next_simple_1(q);

    // Joins:
    // TODO: add _next processing
    // Insert new element into bucket
    // join_insert_bucket_simple_1(q);
    // Compute new join results with other query
    // join_elt_simple_2(&q);
  }

  // If elements expired, trigger aggregation computation
  if (ret > 1) {
    // {{ if window.is_tumbling }}
    // Aggregations:

    // tumble hist
    tumble_hist();

    // tumble average
    tumble_avg();

    // tumble distinct
    // NOTE: for distinct joins, this also functions to tumble the join synopses
    tumble_distinct();

    // {{ else }}

    // See below

    // {{ endif }}

    // Flush window
    ret = window_flush();
    if (ret < 0) {
      ERROR("failed to flush window: %d", ret);
      return 1;
    }

    // Compute new aggregations

    // Histogram:
    hist_quantile(&hist, 99);

    // Distinct joins:

    // Compute number of distinct joins
    u32 n_results = distinct_join_simple_1_simple_2_count();
    if (n_results > 0) {
      // Appease verifier
      if (n_results >= RESULT_SIZE) {
        WARN("number of distinct join results (%lu) exceeds max capacity (%lu); truncating...",
             n_results, RESULT_SIZE);
        n_results = RESULT_SIZE;
      }
      simple_1_simple_2_t *buf =
          bpf_ringbuf_reserve(&ring_buf_8uf3Z, n_results * sizeof(simple_1_simple_2_t), 0);
      if (!buf) {
        ERROR("failed to allocate space on result ringbuf");
        return 1;
      }

      distinct_join_simple_1_simple_2(buf, n_results);

      bpf_ringbuf_submit(buf, 0);
    }
  }

  return 0;
}


// *** LICENSE *** //
char LICENSE[] SEC("license") = "Dual BSD/GPL";


// For step processing (not tumbling), need to iterate through expired elements, since synopses
// aren't built up beforehand
/*
// Remove expired elements from synopses
simple_1_t *w_exp = expired_start();
for (u32 i = 0; i < ret; i++) {
  // Joins:

  // delete from join buckets
  join_delete_bucket_simple_1(w_exp[i]);

  // signal to user-space to delete these records from join result
  // TODO: make join deleted result using ts1, ts2

  // Aggregations:

  // delete from histogram
  hist_delete(&hist, w_exp[i].pfn);

  // delete from avg/distinct

}

// If batch processing, only now update stateful synopses
if (batch_process) {
  simple_1_t *w = elements_start();
  for (u32 i = 0; i < ret; i++) {
    // Joins:

    // Insert element into bucket
    join_insert_bucket_simple_1(w[i]);

    // Insert elements into histograms
    hist_insert(&hist, q.pfn);
  }

  // Compute new join result
  // TODO: take nested loop join from join_next
}
*/