#pragma once

#include "common.bpf.h"


/* Window construction definitions */
// NOTE: although these are window-specific, they are used to estimate sizes in aggregations/joins;
// thus, I've included them here instead.

// Window size
#define WINDOW_SIZE (1 << 15) // 16384
// If count, step == n elements; if time, step == ns.
#define STEP (WINDOW_SIZE)

// {{ if not window.is_count }}
// Time interval, in nanoseconds
#define INTERVAL 1000000000  // aka 1 sec
// {{ endif }}

// For type information, see tracepoint information for mm_filemap_delete_from_page_cache.
// Actual order manually optimizes for padding, but I implemented a struct optimizer, so can just
// reuse.
// TODO: benchmark packed impact on performance hit.
typedef struct simple_1 {
  u64 time;
  u64 pfn;
  u64 i_ino;
  u64 count;  // NOTE: from select; will need to analyze selects in query plan to find new emissions
  u32 s_dev;
  s32 pid;
  s32 tgid;
  char comm[TASK_COMM_LEN];  // pre-defined by vmlinux.h
  s32 ns_pid;                // not rly useful but 🤷 for sake of demonstration
} simple_1_t;                // __attribute__((packed));

const int s = sizeof(simple_1_t);
/* SYNOPSES DEFINITIONS */