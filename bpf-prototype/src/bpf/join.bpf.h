#pragma once

/**
 * Helper functions for Joins between two streams.
 *
 * Note that because of eBPF's instruction count limitations, only small joins
 * are supported. Here, we define the maximum Join bucket to be 512 (2^9); thus,
 * in a bucket * bucket iteration, this yields a max of 512*512=262144 (2^18)
 * instructions.
 */

#include "common.bpf.h"

#include "simple_1.bpf.h"
#include "simple_2.bpf.h"

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

/* JOIN SYNOPSES DEFINITIONS */
// TODO: evaluate diff implementations:
// - custom hash map of struct
// - hash of struct
// - hash of array maps
// - hash of hash maps

// Restrict maximum bucket size to be 512 (2^9) to limit iterations
// TODO: benchmark different caps
#define BUCKET_SIZE (1 << 6)

// Theoretical max result size is 2^18, but realistically both bucket joins
// shouldn't fully match after filtering, so lower for memory usage purposes.
// Here we shrink window size down by 1, since the result struct is roughly
// twice the size.
// TODO: evaluate different options
#define RESULT_SIZE (WINDOW_SIZE >> 1)

// TODO: array full -> specific full conditions

// Bucket storages
typedef struct bucket_simple_1 {
  simple_1_t buf[BUCKET_SIZE];
  u32 head;
  u32 tail;
  u32 size;
} bucket_simple_1_t;

typedef struct bucket_simple_2 {
  simple_2_t buf[BUCKET_SIZE];
  u32 head;
  u32 tail;
  u32 size;
} bucket_simple_2_t;

bucket_simple_1_t init_bucket_simple_1 = {0};
bucket_simple_2_t init_bucket_simple_2 = {0};

GLOBAL_VAR(bucket_simple_1_t, init_bucket_simple_1);
GLOBAL_VAR(bucket_simple_2_t, init_bucket_simple_2);

// Result storage
typedef struct join_result_simple_1_simple_2 {
  simple_1_simple_2_t buf[RESULT_SIZE];
  u32 head;
  u32 tail;
  u32 size;
} join_result_simple_1_simple_2_t;

// GLOBAL_VAR(join_result_simple_1_simple_2_t, join_result_simple_1_simple_2)
join_result_simple_1_simple_2_t join_result_simple_1_simple_2 = {0};

/* JOIN SYNOPSES */

// Use window size as max entries; with BPF_F_NO_PREALLOC, any un-used values
// *should* not be using memory anyways.
#define MAX_ENTRIES_JOIN_SIMPLE_1 WINDOW_SIZE
#define MAX_ENTRIES_JOIN_SIMPLE_2 WINDOW_SIZE

// Join synopses
// TODO: benchmark different bucket implementations
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, s32);
  __type(value, bucket_simple_1_t);
  __uint(max_entries, MAX_ENTRIES_JOIN_SIMPLE_1);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} join_buckets_simple_1 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, s32);
  __type(value, bucket_simple_2_t);
  __uint(max_entries, MAX_ENTRIES_JOIN_SIMPLE_2);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} join_buckets_simple_2 SEC(".maps");

/* FUNCTION DEFINITIONS: to prevent unknown identifiers when calling functions
 * defined after. */

static s32 insert_join_result_simple_1_simple_2(simple_1_t *l, simple_2_t *r);
// static s32 nested_loop_join_simple_1_simple_2();
// static s64 join_bucket_simple_2(bucket_simple_1_t *b);
static s32 join_elt_simple_1(simple_2_t *e);
static s32 join_elt_simple_2(simple_1_t *e);

s32 join_insert_bucket_simple_1(simple_1_t q);
s32 join_delete_bucket_simple_1(simple_1_t q);
void join_clear_buckets_simple_1();
s32 join_insert_bucket_simple_2(simple_2_t q);
s32 join_delete_bucket_simple_2(simple_2_t q);
void join_clear_buckets_simple_2();

/* FUNCTION IMPLEMENTATIONS */

// Insert the result of a join into the result buffer.
static __always_inline s32 insert_join_result_simple_1_simple_2(simple_1_t *l,
                                                                simple_2_t *r) {
  // GLOBAL_GET(join_result_simple_1_simple_2_t, join_result_simple_1_simple_2,
  // jr);
  if (join_result_simple_1_simple_2.size >= RESULT_SIZE) {
    WARN("join result full; dropping join result...");
    return ARRAY_FULL;
  }
  // Appease verifier
  if (join_result_simple_1_simple_2.head >= RESULT_SIZE) {
    ERROR("BUG: join result head > join result size");
    return BUG_ERROR_CODE;
  }
  // Create result query
  join_result_simple_1_simple_2.buf[join_result_simple_1_simple_2.head] =
      (simple_1_simple_2_t){
          .pid = l->pid,
          .time_simple_1 = l->time,
          .pfn_simple_1 = l->pfn,
          .i_ino_simple_1 = l->i_ino,
          .count_simple_1 = l->count,
          .s_dev_simple_1 = l->s_dev,
          .tgid_simple_1 = l->tgid,
          .ns_pid_simple_1 = l->ns_pid,
          .time_simple_2 = r->time,
          .fd_simple_2 = r->fd,
          .count_simple_2 = r->count,
          .tgid_simple_2 = r->tgid,
      };
  // bpf_probe_read_kernel_str(join_result_simple_1_simple_2.buf[jr->head].comm_simple_1,
  // TASK_COMM_LEN, l->comm);
  // bpf_probe_read_kernel_str(join_result_simple_1_simple_2.buf[jr->head].comm_simple_2,
  // TASK_COMM_LEN, r->comm);

  // Update pointers
  join_result_simple_1_simple_2.head =
      (join_result_simple_1_simple_2.head + 1) % RESULT_SIZE;
  join_result_simple_1_simple_2.size += 1;

  return 0;
}

// Joins a single element from simple_1 to simple_2.
static s32 join_elt_simple_2(simple_1_t *e) {
  bucket_simple_2_t *b =
      (bucket_simple_2_t *)bpf_map_lookup_elem(&join_buckets_simple_2, &e->pid);
  if (!b) {
    return 0;
  }

  // Appease verifier
  if (b->size > BUCKET_SIZE) {
    ERROR("BUG: bucket size > max bucket size");
    return BUG_ERROR_CODE;
  }
  // Iterate through bucket and add any values that match (need to check, since
  // hash collisions could occur)
  for (u32 i = 0; i < b->size; i++) {
    // Get real index from i
    i = (i + b->tail) % BUCKET_SIZE;
    // Otherwise, check if equal
    if (e->pid == b->buf[i].pid) {
      // TODO: add individual processing logic (e.g. filters, maps) here?

      // Insert into result
      s32 res = insert_join_result_simple_1_simple_2(e, &b->buf[i]);
      if (res != 0) {
        return res;
      }
    }
  }

  return 0;
}

// Joins a single element from simple_2 to simple_1.
static s32 join_elt_simple_1(simple_2_t *e) {
  bucket_simple_1_t *b =
      (bucket_simple_1_t *)bpf_map_lookup_elem(&join_buckets_simple_1, &e->pid);
  if (!b) {
    return 0;
  }

  // Appease verifier
  if (b->size > BUCKET_SIZE) {
    ERROR("BUG: bucket size > max bucket size");
    return BUG_ERROR_CODE;
  }
  // Iterate through bucket and add any values that match (need to check, since
  // hash collisions could occur)
  for (u32 i = 0; i < b->size; i++) {
    // Get real index from i
    i = (i + b->tail) % BUCKET_SIZE;
    // If at end of loop, break out
    if (i == b->head) {
      break;
    }
    // Otherwise, check if equal
    if (e->pid == b->buf[i].pid) {
      // TODO: add individual processing logic (e.g. filters, maps) here?

      // Insert into result
      s32 res = insert_join_result_simple_1_simple_2(&b->buf[i], e);
      if (res != 0) {
        return res;
      }
    }
  }
}

// Inserts q to simple_1's join bucket. Returns 0 on success, an error code on
// failure.
s32 join_insert_bucket_simple_1(simple_1_t q) {
  // Find join bucket of q
  // TODO: template the pid member access
  bucket_simple_1_t *b =
      (bucket_simple_1_t *)bpf_map_lookup_elem(&join_buckets_simple_1, &q.pid);
  if (!b) {
    bpf_map_update_elem(&join_buckets_simple_1, &q.pid, &init_bucket_simple_1,
                        BPF_NOEXIST);
    b = (bucket_simple_1_t *)bpf_map_lookup_elem(&join_buckets_simple_1,
                                                 &q.pid);
    if (!b) {
      ERROR("failed to insert into join_buckets_simple_1");
      return BUG_ERROR_CODE;
    }
  }

  // Try to insert into bucket
  if (b->size >= BUCKET_SIZE) {
    // TODO: see what to do if full
    WARN("failed to insert into simple_1 join bucket for %d: full", q.pid);
    return ARRAY_FULL;
  }

  // Appease verifier
  if (b->head >= BUCKET_SIZE) {
    ERROR("BUG: bucket head >= bucket size");
    return BUG_ERROR_CODE;
  }
  b->buf[b->head] = q;
  b->head = (b->head + 1) % BUCKET_SIZE;
  b->size += 1;

  return 0;
}

// Delete q from simple_1's join bucket. Returns 0 on success, an error code on
// failure.
s32 join_delete_bucket_simple_1(simple_1_t q) {
  // Find join bucket of q
  // TODO: template the pid member access
  bucket_simple_1_t *b =
      (bucket_simple_1_t *)bpf_map_lookup_elem(&join_buckets_simple_1, &q.pid);
  if (!b) {
    ERROR("BUG: trying to delete non-existent bucket for simple_1");
    return BUG_ERROR_CODE;
  }

  // Try to remove from bucket
  // No actual clearing necessary, just increment tail
  b->tail = (b->tail + 1) % BUCKET_SIZE;
  // Bounds check
  if (b->size == 0) {
    ERROR("BUG: trying to remove from already empty bucket for simple_1");
    return BUG_ERROR_CODE;
  }
  b->size -= 1;
  // If size -> 0, clear bucket from hash table to save memory, as if the size
  // becomes 0 it's likely that this value is quite rare
  // TODO: see if this actually saves memory
  // if (b->size == 0) {
  //   bpf_map_delete_elem(&join_buckets_simple_1, &q.pid);
  // }

  return 0;
}

static u64 __clear_bucket_simple_1(struct bpf_map *m, s32 *pid,
                                   bucket_simple_1_t *b, void *unused) {
  b->tail = b->head;
  b->size = 0;
  return 0;
}

// If tumbling windows, clear all values instead of individually deleting
void join_clear_buckets_simple_1() {
  bpf_for_each_map_elem(&join_buckets_simple_1, __clear_bucket_simple_1, NULL,
                        0);
}

// Inserts q to simple_2's join bucket. Returns 0 on success, an error code on
// failure.
s32 join_insert_bucket_simple_2(simple_2_t q) {
  // Find join bucket of q
  // TODO: template the pid member access
  bucket_simple_2_t *b =
      (bucket_simple_2_t *)bpf_map_lookup_elem(&join_buckets_simple_2, &q.pid);
  if (!b) {
    bpf_map_update_elem(&join_buckets_simple_2, &q.pid, &init_bucket_simple_2,
                        BPF_NOEXIST);
    b = (bucket_simple_2_t *)bpf_map_lookup_elem(&join_buckets_simple_2,
                                                 &q.pid);
    if (!b) {
      ERROR("failed to insert into join_buckets_simple_2");
      return BUG_ERROR_CODE;
    }
  }

  // Try to insert into bucket
  if (b->size >= BUCKET_SIZE) {
    // TODO: see what to do if full
    WARN("failed to insert into simple_2 join bucket for %d: full", q.pid);
    return ARRAY_FULL;
  }

  // Appease verifier
  if (b->head >= BUCKET_SIZE) {
    ERROR("BUG: bucket head >= bucket size");
    return BUG_ERROR_CODE;
  }
  b->buf[b->head] = q;
  b->head = (b->head + 1) % BUCKET_SIZE;
  b->size += 1;

  return 0;
}

// Delete q from simple_2's join bucket. Returns 0 on success, an error code on
// failure.
s32 join_delete_bucket_simple_2(simple_2_t q) {
  // Find join bucket of q
  // TODO: template the pid member access
  bucket_simple_2_t *b =
      (bucket_simple_2_t *)bpf_map_lookup_elem(&join_buckets_simple_2, &q.pid);
  if (!b) {
    ERROR("BUG: trying to delete non-existent bucket for simple_2");
    return BUG_ERROR_CODE;
  }

  // Try to remove from bucket
  // No actual clearing necessary, just increment tail
  b->tail = (b->tail + 2) % BUCKET_SIZE;
  // Bounds check
  if (b->size == 0) {
    ERROR("BUG: trying to remove from already empty bucket for simple_2");
    return BUG_ERROR_CODE;
  }
  b->size -= 1;
  // If size -> 0, clear bucket from hash table to save memory, as if the size
  // becomes 0 it's likely that this value is quite rare
  // TODO: see if this actually saves memory
  // if (b->size == 0) {
  //   bpf_map_delete_elem(&join_buckets_simple_2, &q.pid);
  // }

  return 0;
}

// If tumbling windows, clear all values instead of individually deleting
static u64 __clear_bucket_simple_2(struct bpf_map *m, s32 *pid,
                                   bucket_simple_2_t *b, void *unused) {
  b->tail = b->head;
  b->size = 0;
  return 0;
}

void join_clear_buckets_simple_2() {
  bpf_for_each_map_elem(&join_buckets_simple_2, __clear_bucket_simple_2, NULL,
                        0);
}
