#pragma once

#include "common.bpf.h"

/* Window construction definitions */
// NOTE: although these are window-specific, they are used to estimate sizes in aggregations/joins;
// thus, I've included them here instead.

// Window size
#define WINDOW_SIZE (1 << 15)  // 32768
// If count, step == n elements; if time, step == ns.
#define STEP (WINDOW_SIZE)

// {{ if not window.is_count }}
// Time interval, in nanoseconds
#define INTERVAL 1000000000  // aka 1 sec
// {{ endif }}

// For type information, see tracepoint information for syscalls/sys_enter_pread64.
typedef struct simple_2 {
  u64 time;
  u64 fd;
  u64 count;
  s32 pid;
  s32 tgid;
  char comm[TASK_COMM_LEN];  // pre-defined by vmlinux.h
} simple_2_t;

/* SYNOPSES DEFINITIONS */