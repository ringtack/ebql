#pragma once

/**
 * Distinct join implementation in eBPF for simple_1 + simple_2.
 */

#include "common.bpf.h"
#include "distinct_simple_1.bpf.h"
#include "distinct_simple_2.bpf.h"

// Theoretically, max number of joins is MIN(DISTINCT_MAX_ENTRIES_1, DISTINCT_MAX_ENTRIES_2), since
// each element could match with each other; however, this is very unlikely for even the distinct
// max entries to be hit, or that every element joins with every other.
#define RESULT_SIZE (WINDOW_SIZE >> 1)

// Result definition: combine join field into one value
typedef struct simple_1_simple_2 {
  s32 pid;
  u64 time_simple_1;
  u64 pfn_simple_1;
  u64 i_ino_simple_1;
  u64 count_simple_1;
  u32 s_dev_simple_1;
  s32 tgid_simple_1;
  char comm_simple_1[TASK_COMM_LEN];
  s32 ns_pid_simple_1;
  u64 time_simple_2;
  u64 fd_simple_2;
  u64 count_simple_2;
  s32 tgid_simple_2;
  char comm_simple_2[TASK_COMM_LEN];
} simple_1_simple_2_t;

static __always_inline void make_distinct_join_result_simple_1_simple_2(simple_1_t *l,
                                                                        simple_2_t *r,
                                                                        simple_1_simple_2_t *res) {
  res->pid = l->pid;
  res->time_simple_1 = l->time;
  res->pfn_simple_1 = l->pfn;
  res->i_ino_simple_1 = l->i_ino;
  res->count_simple_1 = l->count;
  res->s_dev_simple_1 = l->s_dev;
  res->tgid_simple_1 = l->tgid;
  res->ns_pid_simple_1 = l->ns_pid;
  res->time_simple_2 = r->time;
  res->fd_simple_2 = r->fd;
  res->count_simple_2 = r->count;
  res->tgid_simple_2 = r->tgid;
  bpf_probe_read_kernel_str(res->comm_simple_1, TASK_COMM_LEN, l->comm);
  bpf_probe_read_kernel_str(res->comm_simple_2, TASK_COMM_LEN, r->comm);
}

// Joins a simple_1_t element to simple_2_t, storing the result in *res if found.
static __always_inline void distinct_join_elt_simple_2(simple_1_t *e, simple_1_simple_2_t *res) {
  // Check if e's join key exists in simple_2's distinct table
  simple_2_t *r = (simple_2_t *)bpf_map_lookup_elem(&distinct_simple_2, &e->pid);
  // If it does exist, make result
  if (r) {
    make_distinct_join_result_simple_1_simple_2(e, r, res);
  }
}

// Joins a simple_2_t element to simple_1_t, storing the result in *res if found.
static __always_inline void distinct_join_elt_simple_1(simple_2_t *e, simple_1_simple_2_t *res) {
  // Check if e's join key exists in simple_2's distinct table
  simple_1_t *l = (simple_1_t *)bpf_map_lookup_elem(&distinct_simple_1, &e->pid);
  // If it does exist, make result
  if (l) {
    make_distinct_join_result_simple_1_simple_2(l, e, res);
  }
}

// Context and callback for computing distinct joins between simple_1 and simple_2.
typedef struct {
  simple_1_simple_2_t *buf;
  u32 buf_sz;
  u32 count;
} distinct_join_simple_1_simple_2_ctx_t;
static s64 __distinct_join_simple_1_simple_2_callback(struct bpf_map *map, u64 *pfn, simple_1_t *l,
                                                      distinct_join_simple_1_simple_2_ctx_t *ctx) {
  // Check if l's join key appears in simple_2's distinct synopsis
  simple_2_t *r = (simple_2_t *)bpf_map_lookup_elem(&distinct_simple_2, &l->pid);
  // If result found, update context
  if (r) {
    if (ctx->count >= ctx->buf_sz) {
      WARN("Distinct join result # exceeds buf size; stopping...");
      return 1;
    }
    make_distinct_join_result_simple_1_simple_2(l, r, &ctx->buf[ctx->count]);
    ctx->count += 1;
  }
  return 0;
}

/**
 * Joins the two tables, outputting results into the passed in buffer, returning the number of
 * elements joined on success, and a negative error code on failure.
 */
static __always_inline s32 distinct_join_simple_1_simple_2(simple_1_simple_2_t *buf, u32 buf_sz) {
  distinct_join_simple_1_simple_2_ctx_t ctx = {
      .buf = buf,
      .buf_sz = buf_sz,
      .count = 0,
  };
  bpf_for_each_map_elem(&distinct_simple_1, __distinct_join_simple_1_simple_2_callback, &ctx, 0);
}

// Callback for distinct join count computation
static s64 __distinct_join_simple_1_simple_2_count_callback(struct bpf_map *map, u64 *pfn,
                                                            simple_1_t *l, u32 *count) {
  simple_2_t *res = bpf_map_lookup_elem(&distinct_simple_2, &l->pid);
  if (res) {
    if (1 /* TODO: add filters here...*/) {
      *count += 1;
    }
  }
  return 0;
}
/**
 * Calculate number of joins there will be.
 */
static __always_inline u32 distinct_join_simple_1_simple_2_count() {
  u32 count = 0;
  bpf_for_each_map_elem(&distinct_simple_1, __distinct_join_simple_1_simple_2_count_callback,
                        &count, 0);
  return count;
}