#pragma once

/**
 * Implement aggregations in eBPF for the query {{query_name}}.
 */

#include "common.bpf.h"
#include "simple_1.bpf.h"
// #include "{{query_name}}.bpf.h"

// Depending on group by key, can reduce number of max entries (e.g. for cpu, only need # cpus)
// #define AGG_MAX_ENTRIES ({{gb_max_entries}})
#define GB_MAX_ENTRIES 32

// Since BPF doesn't allow FP, scale values by AVG_SCALE (4 -> +4 sigfigs)
#define AVG_SCALE (1 << 8)

// Simple aggregations
static __always_inline u64 max(u64 acc, u64 val) { return acc >= val ? acc : val; }
static __always_inline u64 min(u64 acc, u64 val) { return acc <= val ? acc : val; }
static __always_inline u64 count(u64 acc, u64 val) { return acc + 1; }
static __always_inline u64 sum(u64 acc, u64 val) { return acc + val; }
static __always_inline avg_t avg(avg_t acc, u64 val) {
  acc.avg = (acc.avg * acc.count + AVG_SCALE * val) / (acc.count + 1);
  acc.count += 1;
  return acc;
}

typedef struct {
  u64 pid;
  u64 pfn;
} group_by_simple_1_t;

// typedef struct {
//   {{#each group_bys}}
//   {{field_type}} {{field_name}};
//   {{/each}}
// } group_by_{{query_name}}_t;

// Avg counter for individual item.
typedef struct {
  // Note: the averaged value doesn't have to be u64, but do this to prevent
  // overflows.
  u64 avg;
  u64 count;
} avg_t;

// Use val for min/max/count
typedef struct {
  u64 val;
} agg_t;

// {{#each aggs}}
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, group_by_simple_1_t);
  // {{#if is_avg}}
  // __type(value, avg_t);
  // {{else}}
  __type(value, agg_t);
  // {{/if}}
  __uint(max_entries, GB_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} max_pfn_simple_1 SEC(".maps");
// } {{agg}}_{{field}}_{{query_name}} SEC(".maps");
// {{/each}}

// {{#each aggs}}
// static __always_inline s32 insert_{{agg}}_{{field}}_{{query_name}}(u64 val)
static __always_inline s32 insert_max_pfn_simple_1(group_by_simple_1_t key, u64 val) {
  s32 ret;
  // {{#if is_avg}}
  // avg_t *agg = (avg_t *)bpf_map_lookup_elem(&{{agg}}_{{field}}_{{query_name}}, &key);
  // {{else}}
  agg_t *agg = (agg_t *)bpf_map_lookup_elem(&max_pfn_simple_1, &key);
  // {{/if}}
  if (!agg) {
    // {{#if is_avg}}
    avg_t init = {AVG_SCALE * val, 1};
    // {{else}}
    agg_t init = {val};
    // {{/if}}
    // ret = bpf_map_update_elem(&{{agg}}_{{field}}_{{query_name}}, &key, &init, BPF_NOEXIST);
    ret = bpf_map_update_elem(&max_pfn_simple_1, &key, &init, BPF_NOEXIST);
  } else {
    // {{#if is_avg}}
    // agg = {{agg}}(agg, val);
    // {{else}}
    agg->val = max(agg->val, val);
    // {{/if}}
  }
  if (ret != 0) {
    ERROR("failed to insert into {{agg}} map: %d", ret);
  }
  return ret;
}

typedef struct {
  simple_1_t *buf;
  u64 buf_sz;
  u64 count;
  // } {{agg}}_{{field}}_{{query_name}}_ctx_t;
} max_pfn_simple_1_ctx_t;

static __always_inline s64 __get_max_pfn_simple_1_callback(struct bpf_map *map,
                                                           group_by_simple_1_t *key, agg_t *agg,
                                                           max_pfn_simple_1_ctx_t *ctx) {
  // Set agg value
  if (ctx->count >= ctx->buf_sz) {
    WARN("Number of aggregation results exceeds buf size; stopping...");
    return 1;
  }
  // {{#each ../group_bys}}
  // ctx->buf[ctx->count].{{field_name}} = key->{{field_name}};
  ctx->buf[ctx->count].pid = key->pid;
  ctx->buf[ctx->count].pfn = key->pfn;
  // {{/each}}
  // ctx->buf[ctx->count].{{agg}}_{{pfn}}
  ctx->buf[ctx->count].max_pfn = agg->val;
  // {{#if is_avg}}
  // ctx->buf[ctx->count].{{agg}}_{{pfn}}_count = agg->count;
  // {{/if}}
}

// static __always_inline u64 get_{{agg}}_{{field}}_{{query_name}}({{query_name}}_t *buf, u64
// buf_sz) {
static __always_inline u64 get_max_pfn_simple_1(simple_1_t *buf, u64 buf_sz) {
  max_pfn_simple_1_ctx_t ctx = {.buf = buf, .buf_sz = buf_sz, .count = 0};
  bpf_for_each_map_elem(&max_pfn_simple_1, __get_max_pfn_simple_1_callback, &ctx, 0);
}

// {{#if is_avg}}
// static __always_inline u64 __count_{{agg}}_{{field}}_{{query_name}}_callback(struct bpf_map *map,
//                                                              group_by_simple_1_t *key, avg_t
//                                                              *val, u64 *count) {
// {{else}}
static __always_inline s64 __count_max_pfn_simple_1_callback(struct bpf_map *map,
                                                             group_by_simple_1_t *key, agg_t *val,
                                                             u64 *count) {
  // {{/if}}
  *count += 1;
  return 0;
}

// static __always_inline u64 count_{{agg}}_{{field}}_{{query_name}}() {
static __always_inline u64 count_max_pfn_simple_1() {
  u64 count = 0;
  bpf_for_each_map_elem(&max_pfn_simple_1, __count_max_pfn_simple_1_callback, &count, 0);
}

// {{/each}}