#pragma once

/**
 * Implement aggregations in eBPF for the query simple_1.
 */

#include "common.bpf.h"
#include "simple_1.bpf.h"

// Depending on group by key, can reduce number of max entries (e.g. for cpu, only need # cpus)
#define AGG_MAX_ENTRIES (32)

// Since BPF doesn't allow FP, scale values by AVG_SCALE (4 -> +4 sigfigs)
#define AVG_SCALE (10000)

typedef struct {
  u64 pid;
  u64 pfn;
} group_by_simple_1_t;

// Avg counter for individual item.
typedef struct {
  // Note: the averaged value doesn't have to be u64, but do this to prevent
  // overflows.
  u64 val;
  u64 count;
} avg_t;

// Use val for min/max/count
typedef struct {
  u64 val;
} agg_t;

// Simple aggregations
static __always_inline void max(agg_t *agg, u64 val) {
  if (val > agg->val) agg->val = val;
}
static __always_inline void min(agg_t *agg, u64 val) {
  if (val < agg->val) agg->val = val;
}
static __always_inline void count(agg_t *agg, u64 val) { agg->val += 1; }
static __always_inline void sum(agg_t *agg, u64 val) { agg->val += val; }
static __always_inline void avg(avg_t *agg, u64 val) {
  agg->val = (agg->val * agg->count + AVG_SCALE * val) / (agg->count + 1);
  agg->count += 1;
}

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, group_by_simple_1_t);
  __type(value, agg_t);
  __uint(max_entries, AGG_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} max_pid_simple_1 SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, group_by_simple_1_t);
  __type(value, avg_t);
  __uint(max_entries, AGG_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} avg_tgid_simple_1 SEC(".maps");

static __always_inline s32 insert_max_pid_simple_1(group_by_simple_1_t key, u64 val) {
  s32 ret;
  agg_t *agg = (agg_t *)bpf_map_lookup_elem(&max_pid_simple_1, &key);
  if (!agg) {
    agg_t init = {val};
    ret = bpf_map_update_elem(&max_pid_simple_1, &key, &init, BPF_NOEXIST);
  } else {
    max(agg, val);
  }
  if (ret != 0) {
    ERROR("failed to insert into max map: %d", ret);
  }
  return ret;
}

typedef struct {
  simple_1_t *buf;
  u64 buf_sz;
  u64 count;
} max_pid_simple_1_ctx_t;

static __always_inline s64 __get_max_pid_simple_1_callback(struct bpf_map *map,
                                                           group_by_simple_1_t *key, agg_t *agg,
                                                           max_pid_simple_1_ctx_t *ctx) {
  // Set agg value
  if (ctx->count >= ctx->buf_sz) {
    WARN("Number of aggregation results exceeds buf size; stopping...");
    return 1;
  }
  ctx->buf[ctx->count].pid = key->pid;
  ctx->buf[ctx->count].pfn = key->pfn;
  ctx->buf[ctx->count].max_pid = agg->val;
}

static __always_inline u64 get_max_pid_simple_1(simple_1_t *buf, u64 buf_sz) {
  max_pid_simple_1_ctx_t ctx = {.buf = buf, .buf_sz = buf_sz, .count = 0};
  bpf_for_each_map_elem(&max_pid_simple_1, __get_max_pid_simple_1_callback, &ctx, 0);
}

static __always_inline u64 __count_max_pid_simple_1_callback(struct bpf_map *map,
                                                             group_by_simple_1_t *key, void *val,
                                                             u64 *count) {
  *count += 1;
  return 0;
}

static __always_inline u64 count_max_pid_simple_1() {
  u64 count = 0;
  bpf_for_each_map_elem(&max_pid_simple_1, __count_max_pid_simple_1_callback, &count, 0);
}
static __always_inline s32 insert_avg_tgid_simple_1(group_by_simple_1_t key, u64 val) {
  s32 ret;
  avg_t *agg = (avg_t *)bpf_map_lookup_elem(&avg_tgid_simple_1, &key);
  if (!agg) {
    avg_t init = {AVG_SCALE * val, 1};
    ret = bpf_map_update_elem(&avg_tgid_simple_1, &key, &init, BPF_NOEXIST);
  } else {
    avg(agg, val);
  }
  if (ret != 0) {
    ERROR("failed to insert into avg map: %d", ret);
  }
  return ret;
}

typedef struct {
  simple_1_t *buf;
  u64 buf_sz;
  u64 count;
} avg_tgid_simple_1_ctx_t;

static __always_inline s64 __get_avg_tgid_simple_1_callback(struct bpf_map *map,
                                                            group_by_simple_1_t *key, avg_t *agg,
                                                            avg_tgid_simple_1_ctx_t *ctx) {
  // Set agg value
  if (ctx->count >= ctx->buf_sz) {
    WARN("Number of aggregation results exceeds buf size; stopping...");
    return 1;
  }
  ctx->buf[ctx->count].pid = key->pid;
  ctx->buf[ctx->count].pfn = key->pfn;
  ctx->buf[ctx->count].avg_tgid = agg->val;
  ctx->buf[ctx->count].avg_tgid_count = agg->count;
}

static __always_inline u64 get_avg_tgid_simple_1(simple_1_t *buf, u64 buf_sz) {
  avg_tgid_simple_1_ctx_t ctx = {.buf = buf, .buf_sz = buf_sz, .count = 0};
  bpf_for_each_map_elem(&avg_tgid_simple_1, __get_avg_tgid_simple_1_callback, &ctx, 0);
}

static __always_inline u64 __count_avg_tgid_simple_1_callback(struct bpf_map *map,
                                                              group_by_simple_1_t *key, void *val,
                                                              u64 *count) {
  *count += 1;
  return 0;
}

static __always_inline u64 count_avg_tgid_simple_1() {
  u64 count = 0;
  bpf_for_each_map_elem(&avg_tgid_simple_1, __count_avg_tgid_simple_1_callback, &count, 0);
}
