#pragma once

/**
 * Helper functions for computing aggregations.
 */

#include "common.bpf.h"
#include "math.bpf.h"

// Defines some fixed top K to keep, with the assumption that the probability of the next max/min
// occurring in the top K, without being removed on step, is relatively high, so it'd be quicker to
// maintain a local "cache" of next maxes on eviction, rather than linearly scanning through the
// window every time the max is evicted.
#define TOP_K 16

// Total number of slots in the histogram.
#define N_BUCKETS 4

// Value to scale u64s for FP computation (here, 6 means 0.abcdef -> abcdef)
#define FP_SCALE 1e6
// Value to scale inputted quantile values by (since quantile percents are already scaled up, don't
// need to scale by exactly as much)
#define QUANTILE_SCALE FP_SCALE / 1e2

// Individual histogram buckets.
typedef struct hbucket {
  // Bucket lower/upper bounds
  // TODO: float, double, or u64?
  u64 lb;
  u64 ub;
  // Bucket count
  u64 count;
} bucket_t;

// Histogram representation. We assume that buckets are sorted by upper bound (i.e. ub_i < ub_j for
// all i<j); otherwise, histogram bucket and quantile computation will be incorrect.
typedef struct hist {
  bucket_t buckets[N_BUCKETS];
  // Total count across all buckets
  u64 count;
} hist_t;

// TODO: codegen to initialize buckets

// {{ if hist.is_log }}

// Computes bucket of value v in histogram h. Utilizes fast log access, assuming that bucket UBs are
// incremented by powers of 2.
// TODO: see if ptr needed
static u64 __always_inline hist_bucket(hist_t *h, u64 v) {
  u64 slot = log2l(v);
  if (slot >= N_BUCKETS) slot = N_BUCKETS - 1;
  return slot;
}

// {{ else }}

// Computes bucket of value v in histogram h.
// TODO: use binary search
// static u64 __always_inline hist_bucket(hist_t *h, u64 v) {
// #pragma clang loop unroll(full)
//   for (u32 i = 0; i < N_BUCKETS; i++) {
//     u64 lb = h->buckets[i].lb, ub = h->buckets[i].ub;
//     if (lb <= v && v <= ub) {
//       return i;
//     }
//   }
//   return N_BUCKETS - 1;
// }

// {{ endif }}

// Inserts/deletes a value v into/from the histogram.
static void __always_inline hist_insert(hist_t *h, u64 v) {
  u64 slot = hist_bucket(h, v);
  h->buckets[slot].count += 1;
  h->count += 1;
}
static void __always_inline hist_delete(hist_t *h, u64 v) {
  u64 slot = hist_bucket(h, v);
  h->buckets[slot].count -= 1;
  h->count -= 1;
}

// Computes the q quantile (where 0 < q < 100)
// TODO: see if BPF supports fp computations
static u64 __always_inline hist_quantile(hist_t *h, u64 q) {
  // Appease verifier
  if (!h) {
    ERROR("BUG: h is null");
    return BUG_ERROR_CODE;
  }
  if (q == 0 || q > 100) {
    ERROR("q (%lu) must be in (0, 100).", q);
    return EINVAL;
  }
  // If q >= 50, iterate from top down
  u64 total = h->count;
  u64 acc = 0;
  u64 scaled_q = QUANTILE_SCALE * q;
  if (q >= 50) {
    // Scale desired quantile
    u64 prev_pct = FP_SCALE;
    for (u32 i = N_BUCKETS - 1; i >= 0; i--) {
      acc += h->buckets[i].count;
      // Compute the percentile *not* including this bucket
      // For precision, scale bucket counts before computing pct
      u64 b_pct = (FP_SCALE * (total - acc)) / total;
      // If this bucket contains the quantile, return value
      if (b_pct <= scaled_q) {
        u64 lb = h->buckets[i].lb, ub = h->buckets[i].ub;
        // If exactly equal, just return lb (i.e. start of bucket)
        if (b_pct == scaled_q) {
          return lb;
        }
        // Otherwise, compute linear interpolation between buckets
        u64 res = lb + (ub - lb) * (scaled_q - b_pct) / (prev_pct - b_pct);
        return res;
      } else {
        // Otherwise, continue moving down
        prev_pct = b_pct;
      }
    }
  } else {
    // Otherwise, iterate bottom up
    u64 prev_pct = 0;
    for (u32 i = 0; i < N_BUCKETS; i++) {
      acc += h->buckets[i].count;
      // Compute percentile including this bucket
      u64 b_pct = (FP_SCALE * acc) / total;
      // If this bucket contains the quantile, return value
      if (b_pct >= scaled_q) {
        // if exactly equal, return bucket lb
        u64 lb = h->buckets[i].lb, ub = h->buckets[i].ub;
        if (b_pct == scaled_q) {
          return ub;
        }
        // Otherwise, compute linear interpolation between buckets
        u64 res = lb + (ub - lb) * (b_pct - scaled_q) / (b_pct - prev_pct);
        return res;
      } else {
        // Otherwise, move to next bucket
        prev_pct = b_pct;
      }
    }
  }
  ERROR("histogram didn't return value\n");
  return EINVAL;
}
