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
 *
 * RESTRICTIONS (until I can figure out more verifier stuff):
 * - For counts, WINDOW_SIZE % STEP == 0 (i.e. WINDOW_SIZE must be divisible by STEP)
 * - For time, STEP == INTERVAL (i.e. all time windows must be tumbling windows).
 */

#include "common.bpf.h"

// Window construction definitions
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
  if (WINDOW_SIZE % STEP != 0) {
    ERROR("For now (i.e. until I can figure out verifier), STEP must be divisible by WINDOW_SIZE");
    return UNIMPLEMENTED;
  }
  // If window not full, append to end of window
  if (w->w_size < WINDOW_SIZE) {
    // Bounds check for verifier
    if (w->w_head >= WINDOW_SIZE) {
      ERROR("BUG: window.head >= WINDOW_SIZE");
      return BUG_ERROR_CODE;
    }
    w->win[w->w_head] = q;
    // Support wrap-around
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
      // Because STEP divides WINDOW_SIZE, we can always copy in one go
      // Appease verifier
        if (w->w_tail >= WINDOW_SIZE) {
          ERROR("BUG: window.tail >= WINDOW_SIZE");
          return BUG_ERROR_CODE;
        }
      bpf_probe_read_kernel(w->expired, STEP * sizeof(query_simple_t), &w->win[w->w_tail]);
      // Advance tail
      w->w_tail = (w->w_tail + STEP) % WINDOW_SIZE;

      // Copy over new elements
      // Bounds check for verifier
      if (w->w_head >= WINDOW_SIZE) {
        ERROR("BUG: window.head >= WINDOW_SIZE");
        return BUG_ERROR_CODE;
      }
      bpf_probe_read_kernel(&w->win[w->w_head], STEP * sizeof(query_simple_t), w->next);
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
  if (STEP != INTERVAL) {
    ERROR("For now (i.e. until I can figure out verifier), time windows must be tumbling");
    return UNIMPLEMENTED;
  }
  // Since tumbling window, oldest element is always elt_0
  u64 t_since_oldest = q.time - w->win[0].time;
  // Add to window if no elements currently, or within start of this window
  if (w->w_size == 0 || t_since_oldest < INTERVAL) {
    // If full, log warning and drop
    // TODO: figure out better thing to do here; I think could have a global pool of maps as backup?
    if (w->w_size >= WINDOW_SIZE) {
      WARN("Window is full; dropping new event...");
      return ARRAY_FULL;
    }
    w->win[w->w_head] = q;
    // Don't need to account for wrap around, since if size is full we just don't add
    w->w_head++;
    w->w_size++;
  } else {
    // Otherwise, first check if more than (INTERVAL+STEP) time has elapsed since the oldest element
    // in the window; if so, flush all elements and copy over next buffer to window
    if (t_since_oldest > INTERVAL + STEP) {
      // All elements in window are now expired
      expired = w->w_size;
      // Appease verifier
      if (w->w_size > WINDOW_SIZE) {
        ERROR("BUG: window.size > WINDOW_SIZE");
        return BUG_ERROR_CODE;
      }
      // Copy over all elements in window to expired buffer
      // Since window is tumbling, can just copy over entire array
      bpf_probe_read_kernel(w->expired, w->w_size * sizeof(query_simple_t), w->win);
      // Reset tail (NOTE: in tumbling windows, this is unnecessary, since w_tail == 0 always)
      w->w_tail = 0;

      // Copy over new elements to current window
      // Appease verifier
      if (w->next_idx > WINDOW_SIZE) {
        ERROR("BUG: window.next_idx > WINDOW_SIZE");
        return BUG_ERROR_CODE;
      }
      bpf_probe_read_kernel(w->win, w->next_idx * sizeof(query_simple_t), w->next);
      // Update head and window size
      w->w_size = w->w_head = w->next_idx;
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