#pragma once

/**
 * Implement count and avg aggregation in eBPF for the query simple_1.
 */

#include "common.bpf.h"
#include "simple_1.bpf.h"

// In the worst case, every element is distinct, so need at most WINDOW_SIZE entries.
#define AVG_MAX_ENTRIES (WINDOW_SIZE)
// Since BPF doesn't allow FP, scale values by AVG_SCALE (4 -> +4 sigfigs)
#define AVG_SCALE (1 << 8)

// Avg counter for individual item.
typedef struct {
  // Note: the averaged value doesn't have to be u64, but do this to prevent overflows.
  u64 avg;
  u64 count;
} avg_t;

avg_t init_avg = {0};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, avg_t);
  __uint(max_entries, AVG_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} avg_simple_1 SEC(".maps");

// {{ if window.is_tumbling }}
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, avg_t);
  __uint(max_entries, AVG_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} avg_next_simple_1 SEC(".maps");
// {{ endif }}

/**
 * Insert a value into the average count. Returns 0 on success, negative error code on failure.
 */
static __always_inline s32 avg_insert(u64 key, u64 val) {
  s32 ret;
  avg_t *avg = (avg_t *)bpf_map_lookup_elem(&avg_simple_1, &key);
  if (!avg) {
    // If doesn't already exist, insert new counter
    avg_t avg = {AVG_SCALE * val, 1};
    ret = bpf_map_update_elem(&avg_simple_1, &key, &avg, BPF_NOEXIST);
  } else {
    // Otherwise, update counter
    avg->avg = (avg->avg * avg->count + AVG_SCALE * val) / (avg->count + 1);
    avg->count += 1;
    ret = bpf_map_update_elem(&avg_simple_1, &key, &avg, BPF_ANY);
  }
  if (ret < 0) {
    ERROR("Failed to insert into map: %d", ret);
    return ret;
  }
  return 0;
}

/**
 * Delete a value from the next average count. Returns 0 on success, negative error code on failure.
 */
static __always_inline s32 avg_delete(u64 key, u64 val) {
  s32 ret = 0;
  avg_t *avg = (avg_t *)bpf_map_lookup_elem(&avg_simple_1, &key);
  if (!avg) {
    // If doesn't already exist, nothing to delete
    WARN("Trying to delete non-existent value from average (%llu -> %llu)", key, val);
  } else {
    // Otherwise, update counter
    if (avg->count == 1) {
      // If about to become zero, just zero it out
      // TODO: see if deleting from map is better for memory usage
      *avg = (avg_t){0};
    } else {
      avg->avg = (avg->avg * avg->count - AVG_SCALE * val) / (avg->count - 1);
      avg->count -= 1;
    }
    ret = bpf_map_update_elem(&avg_simple_1, &key, &avg, BPF_ANY);
    if (ret < 0) {
      ERROR("Failed to insert into map: %d", ret);
      return ret;
    }
  }
  return 0;
}

// {{ if window.is_tumbling }}

/**
 * Insert a value into the next average count. Returns 0 on success, negative error code on failure.
 */
static __always_inline s32 avg_insert_next(u64 key, u64 val) {
  s32 ret;
  avg_t *avg = (avg_t *)bpf_map_lookup_elem(&avg_next_simple_1, &key);
  if (!avg) {
    // If doesn't already exist, insert new counter
    avg_t avg = {AVG_SCALE * val, 1};
    ret = bpf_map_update_elem(&avg_next_simple_1, &key, &avg, BPF_NOEXIST);
  } else {
    // Otherwise, update counter
    avg->avg = (avg->avg * avg->count + AVG_SCALE * val) / (avg->count + 1);
    avg->count += 1;
    ret = bpf_map_update_elem(&avg_next_simple_1, &key, &avg, BPF_ANY);
  }
  if (ret < 0) {
    ERROR("Failed to insert into map: %d", ret);
    return ret;
  }
  return 0;
}

/**
 * Delete a value from the next average count. Returns 0 on success, negative error code on failure.
 */
static __always_inline s32 avg_delete_next(u64 key, u64 val) {
  s32 ret = 0;
  avg_t *avg = (avg_t *)bpf_map_lookup_elem(&avg_next_simple_1, &key);
  if (!avg) {
    // If doesn't already exist, nothing to delete
    WARN("Trying to delete non-existent value from average (%llu -> %llu)", key, val);
  } else {
    // Otherwise, update counter
    if (avg->count == 1) {
      // If about to become zero, just zero it out
      // TODO: see if deleting from map is better for memory usage
      *avg = (avg_t){0};
    } else {
      avg->avg = (avg->avg * avg->count - AVG_SCALE * val) / (avg->count - 1);
      avg->count -= 1;
    }
    ret = bpf_map_update_elem(&avg_next_simple_1, &key, &avg, BPF_ANY);
    if (ret < 0) {
      ERROR("Failed to insert into map: %d", ret);
      return ret;
    }
  }
  return 0;
}

static __always_inline s64 __tumble_avg_clear_callback(struct bpf_map *map, u64 *key, avg_t *avg,
                                                       void *unused) {
  *avg = (avg_t){0};
  return 0;
}
static __always_inline s64 __tumble_avg_copy_callback(struct bpf_map *map, u64 *key, avg_t *avg,
                                                      void *unused) {
  s64 ret = bpf_map_update_elem(&avg_simple_1, key, avg, BPF_ANY);
  if (ret != 0) {
    ERROR("failed to copy over key %d's average to avg_simple_1", *key);
    return 1;
  }
  return 0;
}

/**
 * Migrate values from avg_next to avg. Applies only to tumbling windows.
 */
static __always_inline void tumble_avg() {
  // First, zero out elements in avg so we don't have any leftovers
  bpf_for_each_map_elem(&avg_simple_1, __tumble_avg_clear_callback, NULL, 0);
  // Then, copy elements over from avg_next to avg
  bpf_for_each_map_elem(&avg_next_simple_1, __tumble_avg_copy_callback, NULL, 0);
}

// {{ endif }}