#pragma once

/**
 * Bit computations.
 *
 * Credit to bcc/libbpf-tools for log2 implementation.
 */

#include "common.bpf.h"

// Basic math stuff
#define MS_TO_NS 1000000U
#define NS_TO_MS 0.000001

#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))

static __always_inline u64 log2(u32 v) {
  u32 shift, r;

  r = (v > 0xFFFF) << 4;
  v >>= r;
  shift = (v > 0xFF) << 3;
  v >>= shift;
  r |= shift;
  shift = (v > 0xF) << 2;
  v >>= shift;
  r |= shift;
  shift = (v > 0x3) << 1;
  v >>= shift;
  r |= shift;
  r |= (v >> 1);

  return r;
}

static __always_inline u64 log2l(u64 v) {
  u32 hi = v >> 32;

  if (hi)
    return log2(hi) + 32;
  else
    return log2(v);
}