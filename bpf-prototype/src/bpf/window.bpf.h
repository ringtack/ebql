#pragma once

/**
 * Windowing capabilities that turn eBPF event streams into bounded relations.
 * Three window types are supported:
 * - Count(N, step): Stores a window of N elements, with a step <= N.
 * - Time(Interval, step): Stores a window of interval time span, with step <=
 * interval.
 * - TODO: Session(threshold): Stores a window by sessions of activity, with an
 * inactivity threshold.
 *
 * Stream processing occurs only when the step is triggered (e.g. the step
 * duration elapsed in a time interval).
 *
 * RESTRICTIONS (until I can figure out more verifier stuff):
 * - For counts, WINDOW_SIZE % STEP == 0 (i.e. WINDOW_SIZE must be divisible by
 * STEP)
 * - For time, STEP == INTERVAL (i.e. all time windows must be tumbling
 * windows).
 */

#include "common.bpf.h"
#include "simple_1.bpf.h"

// Window representation. Separate win and next, since max allowed map size is
// 4MB.
typedef struct window {
  // Window storage: window itself, next step, and scratch space for expired
  // values.
  simple_1_t buf[WINDOW_SIZE];

  // Window metadata
  u32 head;
  u32 tail;
  u32 size;
} window_t;

typedef struct next {
  // {{ if window.is_count }}
  simple_1_t buf[STEP];
  // {{ else }}
  // simple_1_t next[WINDOW_SIZE];
  // {{ endif }}
  u32 idx;
} next_t;

// Global window state representation
// window_t w = {0};
// // Next buffer
// next_t next = {0};

GLOBAL_VAR(window_t, window)
GLOBAL_VAR(next_t, next)

/**
 * Checks if a window has expired values; if so, returns the number of expired
 * values.
 */
// {{ if window.is_count }}
static u32 __always_inline window_expired() {
  GLOBAL_GET(next_t, next, n);
  if (n->idx + 1 == STEP)
    return STEP;
  else
    return 0;
}
// {{ else }}
// static u32 __always_inline window_expired(u64 t) {
//   u64 t_since_oldest = t - w.buf[0].time;
//   if (w.size > 0 && t_since_oldest > INTERVAL + STEP)
//     return w.size;
//   else
//     return 0;
// }
// {{ endif }}

/**
 * Gets the start of the expired elements. Since it's either a tumbling window
 * or step divides window size, can just iterate normally; don't need to worry
 * about wrap-arounds.
 */
static __always_inline simple_1_t *expired_start() {
  GLOBAL_GET(window_t, window, w);
  return &w->buf[w->tail];
}

/**
 * Gets the start of the valid elements. This has the same logic as
 * expired_start, but must be called *after* being flushed.
 */
static __always_inline simple_1_t *elements_start() {
  GLOBAL_GET(window_t, window, w);
  return &w->buf[w->tail];
}

/**
 * Appends an element to the window. If elements are expired, copy over next
 * buffer to window, then clears next buffer. Returns:
 * - # of elements to flush if window has expired elements
 * - 1 if the element goes into the next step buffer
 * - 0 if the element goes into the window
 * - Error code on failure
 *
 * NOTE: Be sure to iterate through expired elements with expired_iter *before*
 * calling window_add; otherwise, expired elements may be overwritten (for
 * tumbling windows).
 *
 * TODO: to inline, or not to inline?
 * TODO: is it worth to convert q into a pointer too? in case queries get large
 */
static __always_inline s32 window_add(simple_1_t q) {
  GLOBAL_GET(window_t, window, w);
  GLOBAL_GET(next_t, next, n);

  // {{ if window->is_count }}
  // COUNT WINDOW COMPUTATION
  if (WINDOW_SIZE % STEP != 0) {
    ERROR("For now (i.e. until I can figure out verifier), STEP must be "
          "divisible by WINDOW_SIZE");
    return -UNIMPLEMENTED;
  }
  // If window not full, append to end of window
  if (w->size < WINDOW_SIZE) {
    // Bounds check for verifier
    if (w->head >= WINDOW_SIZE) {
      ERROR("BUG: window->head >= WINDOW_SIZE");
      return -BUG_ERROR_CODE;
    }
    w->buf[w->head] = q;
    // Support wrap-around
    w->head = (w->head + 1) % WINDOW_SIZE;
    w->size++;
    return 0;
  } else {
    // Otherwise, append to end of step
    // Bounds check for verifier
    if (n->idx >= STEP) {
      ERROR("BUG: next->idx >= STEP");
      return -BUG_ERROR_CODE;
    }
    n->buf[n->idx] = q;
    n->idx++;
    // If step becomes full, migrate new elements to buffer
    if (n->idx == STEP) {
      return STEP;
    }
    return 1;
  }
  // {{ else }}
  // TIME WINDOW COMPUTATION
  if (STEP != INTERVAL) {
    ERROR("For now (i.e. until I can figure out verifier), time windows must "
          "be tumbling");
    return -UNIMPLEMENTED;
  }
  // Since tumbling window, oldest element is always elt_0
  u64 t_since_oldest = q.time - w->buf[0].time;
  // Add to window if no elements currently, or within start of this window
  if (w->size == 0 || t_since_oldest < INTERVAL) {
    // If full, log warning and drop
    // TODO: figure out better thing to do here; I think could have a global
    // pool of maps as backup?
    if (w->size >= WINDOW_SIZE) {
      WARN("Window is full; dropping new event...");
      return -ARRAY_FULL;
    }
    w->buf[w->head] = q;
    // Don't need to account for wrap around, since if size is full we just
    // don't add
    w->head++;
    w->size++;
    return 0;
  } else {
    // Only add to window if not already full
    // TODO: figure out better thing to do here
    if (n->idx >= WINDOW_SIZE) {
      WARN("Next step buffer is full; dropping new event...");
    } else {
      // Add to next window
      n->buf[n->idx] = q;
      // No modulo needed, since copying over functionally clears w->next, so
      // it'll always be <= WINDOW_SIZE
      n->idx++;
    }
    // If more than (INTERVAL+STEP) time has elapsed since the oldest element in
    // the window, copy over next buffer to window and clear next buffer NOTE:
    // in the worst case of the window being full, this permits one less element
    // than maximally possible, since it'd be optimal to flush before inserting.
    // However, this makes the logic much more annoying, so we'll just go with
    // this for now.
    if (t_since_oldest > INTERVAL + STEP) {
      // Since time windows must be tumbling, all elements in the window are now
      // expired
      return w->size;
    }
    return 1;
  }
  // {{ endif }}

  return 0;
}

/**
 * Flushes the window. Returns the number of new valid elements in the window on
 * success, a negative error code on failure.
 */
static s32 __always_inline window_flush() {
  GLOBAL_GET(window_t, window, w);
  GLOBAL_GET(next_t, next, n);

  // {{ if window.is_count }}
  // Bounds check for verifier
  if (w->head > WINDOW_SIZE - STEP) {
    ERROR("BUG: window->head >= WINDOW_SIZE");
    return -BUG_ERROR_CODE;
  }
  bpf_probe_read_kernel(&w->buf[w->head], STEP * sizeof(simple_1_t), n->buf);
  // Advance tail and head
  w->tail = (w->tail + STEP) % WINDOW_SIZE;
  w->head = (w->head + STEP) % WINDOW_SIZE;
  // Reset next index
  n->idx = 0;

  // Note that in a count window, once the window is full the size never
  // decreases; items stay in the window until they're pushed out by the next
  // step, but the total amount doesn't change

  // {{ else }}

  // All elements in window are now expired
  // Appease verifier
  if (n->idx > WINDOW_SIZE) {
    ERROR("BUG: next->idx > WINDOW_SIZE");
    return -BUG_ERROR_CODE;
  }

  bpf_probe_read_kernel(w->buf, n->idx * sizeof(simple_1_t), n->buf);
  // Update head and window size to # of new elements
  w->size = w->head = n->idx;
  // Reset next buffer back to beginning (note that in tumbling windows, tail =
  // 0 always, so this isn't actually necessary)
  w->tail = n->idx = 0;

  // {{ endif }}

  // Return new window size
  return w->size;
}

/**
 * Iterate over expired elements.
 *
 * Macro, to allow for arbitrary code to be written
 */
#define expired_iter(n_expired, var)                                           \
  for (u32 i = 0; i < n_expired; i++) {                                        \
    simple_1_t var = w.buf[(w.tail + i) % WINDOW_SIZE];

/**
 * End expired iter
 */
#define end_expired_iter }

#define list_iterate(list, var, type, member)                                  \
    for (type *var = list_head(list, type, member),         \
              *__next_##var = list_next(var, type, member); \
         &var->member != (list);                            \