#pragma once

/**
 * Windowing capabilities that turn eBPF event streams into bounded relations. Three window types
 * are supported:
 * - Count(N, step): Stores a window of N elements, with a step <= N.
 * - Time(Interval, step): Stores a window of interval time span, with step <= interval.
 * - TODO: Session(threshold): Stores a window by sessions of activity, with an inactivity
 * threshold.
 *
 * Stream processing occurs only when the step is triggered (e.g. the step duration elapsed in a
 * time interval).
 */

#include "common.bpf.h"

// Window construction definitions
// TODO: maybe change buffer size to a diff variable, and in time windows, make it a const volatile
// to update if too much data; I think we can run-time replace a map
// ^ But this requires a map-of-maps, which incurs significant runtime overhead w/ bounds
// checking... perhaps better idea is to perform PGO in query optimization (likely that this is
// necessary anyways for opt purposes), then adjust window size w/ a new program then??
#define WINDOW_SIZE 1024  // TODO: tmpl
// If count, step == n elements; if time, step == ns.
#define STEP 16

// {{ if not window.is_count }}
// Time interval, in nanoseconds
#define INTERVAL 1000000000  // aka 1 sec
// {{ endif }}

typedef struct query_simple {
	u64 time;
  u64 pfn;
  u64 i_ino;
  u64 count;  // NOTE: from select; will need to analyze selects in query plan to find new emissions
  u32 s_dev;
  s32 pid;
  s32 tgid;
  char comm[TASK_COMM_LEN]; // pre-defined by vmlinux.h
  s32 ns_pid; // not rly useful but 🤷 for sake of demonstration
} query_simple_t;  // __attribute__((packed));

typedef struct window {
  // Window storage: window itself, next step, and scratch space for expired values.
  query_simple_t win[WINDOW_SIZE];
  // {{ if window.is_count }}
  query_simple_t next[STEP];
  query_simple_t expired[STEP];
  // {{ else }}
  // TODO: see if we can shrink these
  // query_simple_t next[WINDOW_SIZE];
  // query_simple_t expired[WINDOW_SIZE];
  // {{ endif }}

  // Window metadata
  u32 w_head;
  u32 w_tail;
  u32 w_size;
  u32 next_idx;
} window_t;

// Appends an element to the window. If window flushing is needed, returns the number of elements
// expired.
// TODO: benchmark inlining
// TODO: see if w/q needs to be pointer if function is inlined
static u32 __always_inline window_add(window_t *w, query_simple_t q) {
  u32 expired = 0;
  // TODO: see if this is necessary if always inlined
  if (!w) {
    ERROR("provided null values that should never be null");
    return BUG_ERROR_CODE;
  }
  // {{ if window.is_count }}
  // COUNT WINDOW COMPUTATION
  // If window not full, append to end of window
  if (w->w_size < WINDOW_SIZE) {
    // Bounds check for verifier
    if (w->w_head >= WINDOW_SIZE) {
      ERROR("BUG: window.head >= WINDOW_SIZE");
      return BUG_ERROR_CODE;
    }
    w->win[w->w_head] = q;
    // Support wrap-around TODO: check if Clang optimizes power-of-2 mods
    w->w_head = (w->w_head + 1) % WINDOW_SIZE;
    w->w_size++;
  } else {
    // Otherwise, append to end of step
    // Bounds check for verifier
    if (w->next_idx >= STEP) {
      ERROR("BUG: w->next_idx >= STEP");
      return BUG_ERROR_CODE;
    }
    w->next[w->next_idx] = q;
    w->next_idx++;
    // If step becomes full, migrate elements to be expired, and new elements
    if (w->next_idx == STEP) {
      // Copy over elements to be expired
      // Check if we can copy over in one memcpy
      if (w->w_tail + STEP <= WINDOW_SIZE) {
        // We use bpf_probe_read_kernel, because __builtin_memcpy works only when the amount
        // to copy < 512B; otherwise, it exceeds the BPF stack size limit.
        bpf_probe_read_kernel(w->expired, STEP * sizeof(query_simple_t), &w->win[w->w_tail]);
      } else {
        // Appease the verifier
        if (w->w_tail >= WINDOW_SIZE) {
          ERROR("BUG: window.tail >= WINDOW_SIZE");
          return BUG_ERROR_CODE;
        }
        u32 n = WINDOW_SIZE - w->w_tail;
        if (n >= STEP) {
          ERROR("BUG: window.tail >= WINDOW_SIZE");
          return BUG_ERROR_CODE;
        }
        // TODO: HELP
        // Copy over [tail, WINDOW_SIZE) aka n elements
        bpf_probe_read_kernel(w->expired, n * sizeof(query_simple_t), &w->win[w->w_tail]);
        // Copy over [0, STEP - n) aka STEP - n elements
        bpf_probe_read_kernel(&w->expired[n], (STEP - n) * sizeof(query_simple_t), w->win);
      }
      // Advance tail
      w->w_tail = (w->w_tail + STEP) % WINDOW_SIZE;

      // Copy over new elements
      // Check if we can copy over in one memcpy
      // Bounds check for verifier
      if (w->w_head >= WINDOW_SIZE) {
        ERROR("BUG: window.head >= WINDOW_SIZE");
        return BUG_ERROR_CODE;
      }
      if (w->w_head + STEP <= WINDOW_SIZE) {
        bpf_probe_read_kernel(&w->win[w->w_head], STEP * sizeof(query_simple_t), w->next);
      } else {
        u32 n = WINDOW_SIZE - w->w_head;
        // Copy over first n elements to [head, WINDOW_SIZE)
        bpf_probe_read_kernel(&w->win[w->w_head],  n * sizeof(query_simple_t), w->next);
        // Copy over remaining elements to [0, STEP - n)
        bpf_probe_read_kernel(w->win, (STEP - n) * sizeof(query_simple_t), &w->next[n]);
      }
      // Advance head
      w->w_head = (w->w_head + STEP) % WINDOW_SIZE;
      // Reset next index
      w->next_idx = 0;

      // Note that in a count window, once the window is full the size never decreases; items stay
      // in the window until they're pushed out by the next step, but the total amount doesn't
      // change
      expired = STEP;
    }
  }
  // {{ else }}
  // TIME WINDOW COMPUTATION
  // if ts(q) - ts(elt_0) < interval, add to window
  // Bounds check for verifier
  if (w->w_tail >= WINDOW_SIZE) {
      ERROR("BUG: window.tail >= WINDOW_SIZE");
      return BUG_ERROR_CODE;
  }
  if (w->w_head >= WINDOW_SIZE) {
    ERROR("BUG: window.head >= WINDOW_SIZE");
    return BUG_ERROR_CODE;
  }
  u64 t_since_oldest = q.time - w->win[w->w_tail].time;
  if (t_since_oldest < INTERVAL) {
    // If full, log warning and drop
    // TODO: figure out better thing to do here; I think could have a global pool of maps as backup?
    if (w->w_size >= WINDOW_SIZE) {
      WARN("Window is full; dropping new event...");
      return ARRAY_FULL;
    }
    w->win[w->w_head] = q;
    w->w_head = (w->w_head + 1) % WINDOW_SIZE;
    w->w_size++;
  } else {
    // Otherwise, first check if more than (INTERVAL+STEP) time has elapsed since the oldest element
    // in the window; if so, flush all elements and copy over next buffer to window
    if (t_since_oldest > (INTERVAL + STEP)) {
      // Find new oldest time in window
      u32 new_oldest_t = w->win[w->w_tail].time + STEP;
      // Find new tail
      u32 new_tail = w->w_tail;
      // Special-case for tumbling windows
      if (INTERVAL == STEP) {
        // For tumbling windows, new_tail == w->w_head
        new_tail = w->w_head;
      } else {
        // Appease verifier
        // TODO: time-permitting, implement binary search on circular buffer
        // (https://stackoverflow.com/a/2835066/15140014)
        for (u32 i = 0; i < WINDOW_SIZE; i++) {
          if (w->win[new_tail].time >= new_oldest_t) break;
          new_tail = (new_tail + 1) % WINDOW_SIZE;
        }
      }

      // Copy over expired values
      expired = (new_tail != w->w_tail)
                    // Add WINDOW_SIZE to handle cases in which new_tail < old_tail
                    ? (new_tail + WINDOW_SIZE - w->w_tail) % WINDOW_SIZE
                    // If new_tail == old_tail, window is full, so copy over everything
                    : WINDOW_SIZE;
      // Check if we can copy over in one memcpy; can't do == here, since if new_tail != 0, expired
      // can be WINDOW_SIZE and so an overflow could occur
      if (w->w_tail < new_tail) {
        bpf_probe_read_kernel(w->expired, expired * sizeof(query_simple_t), &w->win[w->w_tail]);
      } else {
        u32 n = WINDOW_SIZE - w->w_tail;
        // Copy [old_tail, WINDOW_SIZE) aka n elements
        bpf_probe_read_kernel(w->expired, n * sizeof(query_simple_t), &w->win[w->w_tail]);
        // Copy remaining [0, expired-n) aka expired-n elements
        bpf_probe_read_kernel(&w->expired[n], (expired - n) * sizeof(query_simple_t), w->win);
      }
      // Advance tail
      w->w_tail = new_tail;

      // Copy over next buffer to window
      // Appease the verifier
      if (w->w_head >= WINDOW_SIZE) {
        ERROR("BUG: window.head >= WINDOW_SIZE");
        return BUG_ERROR_CODE;
      }
      // NOTE: HAD TO ADD
      if (w->next_idx > WINDOW_SIZE) {
        ERROR("BUG: window.next_idx > WINDOW_SIZE");
        return BUG_ERROR_CODE;
      }
      // Check if we can copy over in one memcpy; here next_idx == # of new elements in next window
      if (w->w_head + w->next_idx <= WINDOW_SIZE) {
        bpf_probe_read_kernel(&w->win[w->w_head], w->next_idx * sizeof(query_simple_t), w->next);
      } else {
        u32 n = WINDOW_SIZE - w->w_head;
        bpf_probe_read_kernel(&w->win[w->w_head], n * sizeof(query_simple_t), w->next);
        // Appease the verifier, since it can't verify from L213 that next_idx > n ...
        if (w->next_idx < n) {
          ERROR("BUG: window.next_idx < n");
          return BUG_ERROR_CODE;
        }
        if (n > WINDOW_SIZE) {
          return BUG_ERROR_CODE;
        }
        u32 ub = WINDOW_SIZE - n;
        u32 left = w->next_idx - n;
        if (left >= ub) {
          left = ub;
        }
        // bpf_probe_read_kernel(w->win, ub * sizeof(query_simple_t), &w->next[n]);
        // TODO: HELP
        bpf_probe_read_kernel(w->win, left * sizeof(query_simple_t), &w->next[n]);

      }
      // Advance head
      w->w_head = (w->w_head + w->next_idx) % WINDOW_SIZE;
      // Here, window size might change: window lost expired items, but gained next_idx items
      w->w_size = w->w_size + w->next_idx - expired;
      // Reset next buffer back to beginning
      w->next_idx = 0;
    } else {
      // Check only necessary if we didn't step; otherwise next_idx goes back to 0
      // TODO: figure out better thing to do here
      if (w->next_idx >= WINDOW_SIZE) {
        WARN("Next step buffer is full; dropping new event...");
        return ARRAY_FULL;
      }
    }
    // Add to next window
    w->next[w->next_idx] = q;
    // No modulo needed, since copying over functionally clears w->next
    w->next_idx++;
  }
  // {{ endif }}

  return expired;
}