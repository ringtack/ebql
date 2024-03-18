#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h>

#include "vmlinux.h" /* all kernel types */

/*
From Andrii Nakryiko's blog (https://nakryiko.com/posts/libbpf-bootstrap/#bpf-maps):

  volatile is necessary to make sure Clang doesn't optimize away the variable altogether, ignoring
  user-space provided value. Without it, Clang is free to just assume 0 and remove the variable
  completely, which is not at all what we want.
*/
const volatile uint32_t target_pid = 0;

// PERF_EVENT_ARRAY to communicate with userspace
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} perf_buffer SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  //__uint(max_entries, 100);
  __uint(max_entries, 256);
} tid_start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct syscall_event_buffer);
  __uint(max_entries, 1);
} syscall_buffers SEC(".maps");

struct syscall_event {
  uint32_t pid;
  uint32_t tid;
  uint64_t syscall_number;
  uint64_t start_time;
  uint64_t duration;
};

struct syscall_event_buffer {
  uint32_t length;
  struct syscall_event buffer[256];
};

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
  // Get task, and check task tgid/pid
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  struct task_struct *task = bpf_get_current_task();
  uint32_t pid = 0, tid = 0;
  bpf_probe_read(&pid, sizeof(pid), &task->tgid);
  bpf_probe_read(&tid, sizeof(tid), &task->pid);

  // Check if desired pid
  if ((target_pid == 0) || (pid == target_pid)) {
    uint64_t time = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&tid_start, &tid, &time, BPF_ANY) == 0) {
      bpf_printk("ERROR: could not set start time for pid %d\n", tid);
    }
  }
  return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx) {
  // Get task, and check task tgid/pid
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  uint32_t pid = 0, tid = 0;
  bpf_probe_read(&pid, sizeof(pid), &task->tgid);
  bpf_probe_read(&tid, sizeof(tid), &task->pid);

  // Check if desired pid
  if ((target_pid == 0) || (target_pid == pid)) {
    uint64_t end = bpf_ktime_get_ns();
    uint64_t *start = bpf_map_lookup_elem(&tid_start, &tid);
    if (!start) {
      bpf_printk("ERROR: sys_exit for pid %d does not have corresponding sys_enter\n", tid);
    }
    int sysno = ctx->id;
    struct syscall_event e = {0};
    e.pid = pid;
    e.tid = tid;
    e.duration = end - *start;
    e.syscall_number = sysno;
    e.start_time = *start;

    int zero = 0;
    struct syscall_event_buffer *buffer = bpf_map_lookup_elem(&syscall_buffers, &zero);
    if (!buffer) {
      bpf_printk("ERROR GETTING BUFFER");
      return 0;
    }

    if (buffer->length < 256) {
      buffer->buffer[buffer->length] = e;
      buffer->length += 1;
    }

    if (buffer->length == 256) {
      bpf_perf_event_output((void *)ctx, &perf_buffer, BPF_F_CURRENT_CPU, buffer, sizeof(*buffer));
      buffer->length = 0;
    }
  }
  return 0;
}