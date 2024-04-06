#pragma once

/**
 * Generic helper functions and utilities for BPF programs.
 *
 * Credit to https://github.com/QMUL-EECS-Networks-Systems/ebpf-sketches/tree/main/src/ebpf for
 * some of the utility functions.
 */

#include "vmlinux.h"           /* All available kernel types */
#include <bpf/bpf_core_read.h> /* BPF CO-RE helpers */
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc. */
#include <bpf/bpf_tracing.h>   /* TODO: find purpose */

// Return values
#define BUG_ERROR_CODE 0xDADBEEF
#define EINVAL 22
#define ARRAY_FULL 0xBADBEEF

// Compute array size
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

// Color codes
#define RED "\033[0;31m"
#define YELLOW "\033[0;33m"
#define BLUE "\033[0;34m"
#define NC "\033[0m"

// Log utilities
#define DEBUG(fmt, ...)                                               \
  ({                                                                  \
    if (LOG_LVL >= L_DEBUG) bpf_printk("DEBUG: " fmt, ##__VA_ARGS__); \
  })
#define INFO(fmt, ...)                                                      \
  ({                                                                        \
    if (LOG_LVL >= L_INFO) bpf_printk(BLUE "INFO: " NC fmt, ##__VA_ARGS__); \
  })
#define WARN(fmt, ...)                                                        \
  ({                                                                          \
    if (LOG_LVL >= L_WARN) bpf_printk(YELLOW "WARN: " NC fmt, ##__VA_ARGS__); \
  })
#define ERROR(fmt, ...)                                                      \
  ({                                                                         \
    if (LOG_LVL >= L_ERROR) bpf_printk(RED "ERROR: " NC fmt, ##__VA_ARGS__); \
  })

// Log level. Default is L_DEBUG.
enum LOG_LEVEL { L_DEBUG = 0, L_INFO, L_WARN, L_ERROR };
const volatile u8 LOG_LVL = L_DEBUG;

// Compute the average of two ints (s32s) without overflow.
static int average_without_overflow(s32 a, s32 b) { return (a & b) + ((a ^ b) >> 1); }