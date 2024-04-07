#pragma once

/**
 * Implement distinct functionality in eBPF for the query simple_2.
 */

#include "common.bpf.h"
#include "simple_2.bpf.h"

// In the worst case, every element is distinct, so need at most WINDOW_SIZE entries.
#define DISTINCT_MAX_ENTRIES (WINDOW_SIZE)

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, simple_2_t);
  __uint(max_entries, DISTINCT_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} distinct_simple_2 SEC(".maps");

// {{ if window.is_tumbling }}
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, simple_2_t);
  __uint(max_entries, DISTINCT_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} distinct_next_simple_2 SEC(".maps");
// {{ endif }}

/**
 * Inserts the value into the distinct synopsis. Our distinct semantics are that newer elements take
 * priority in the "distinct" value; thus, all this does is update the map element. Returns 0 on
 * success, negative error code on failure.
 */
static __always_inline s32 distinct_insert(simple_2_t q) {
  // TODO: replace pid with distinct group by key
  s32 ret = bpf_map_update_elem(&distinct_simple_2, &q.pid, &q, BPF_ANY);
  return ret;
}

/**
 * Deletes an element from the distinct synopsis.
 */
static __always_inline s32 distinct_delete(simple_2_t q) {
  s32 ret = bpf_map_delete_elem(&distinct_simple_2, &q.pid);
  return ret;
}

// {{ if window.is_tumbling }}

/**
 * Inserts the value into the next distinct synopsis.
 */
static __always_inline s32 distinct_insert_next(simple_2_t q) {
  // TODO: replace pid with distinct group by key
  s32 ret = bpf_map_update_elem(&distinct_next_simple_2, &q.pid, &q, BPF_ANY);
  return ret;
}

/**
 * Deletes an element from the next distinct synopsis.
 */
static __always_inline s32 distinct_delete_next(simple_2_t q) {
  s32 ret = bpf_map_delete_elem(&distinct_next_simple_2, &q.pid);
  return ret;
}

static __always_inline s64 __tumble_distinct_clear_callback(struct bpf_map *map, u64 *key,
                                                            simple_2_t *q, void *unused) {
  *q = (simple_2_t){0};
  return 0;
}
static __always_inline s64 __tumble_distinct_copy_callback(struct bpf_map *map, u64 *key,
                                                           simple_2_t *q, void *unused) {
  s64 ret = bpf_map_update_elem(&distinct_simple_2, key, q, BPF_ANY);
  if (ret != 0) {
    ERROR("failed to copy over key %d's average to avg_simple_2", *key);
    return 1;
  }
  return 0;
}

/**
 * Migrate values from distinct_next to distinct. Applies only to tumbling windows.
 */
static __always_inline void tumble_distinct() {
  // First, zero out elements in avg so we don't have any leftovers
  bpf_for_each_map_elem(&distinct_simple_2, __tumble_distinct_clear_callback, NULL, 0);
  // Then, copy elements over from avg_next to avg
  bpf_for_each_map_elem(&distinct_next_simple_2, __tumble_distinct_copy_callback, NULL, 0);
}

// {{ endif }}