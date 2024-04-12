// *** INCLUDES SECTION *** //
#include "vmlinux.h" /* all kernel types */
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used_helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /*  */


// *** DEFINITIONS SECTION *** //
struct select_0E1Ra {
	u64 fd;
	u64 count;
	u64 time;
	s32 pid;
} __attribute__((packed));
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ring_buf_b5S24 SEC(".maps");


// *** GLOBALS SECTION *** //


// *** CODE SECTION *** //
SEC("tracepoint/syscalls/sys_enter_pread64")
u32 bpf_select_itgTr(struct trace_event_raw_sys_enter * ctx) {
	bpf_printk("got event\n");
	struct select_0E1Ra * e = bpf_ringbuf_reserve(&ring_buf_b5S24, sizeof(struct select_0E1Ra), 0);
	if (!e) {	
bpf_printk("failed to allocate values\n");
	
return 1;
	}
	e->fd = (u64) ctx->args[0];
	e->count = (u64) ctx->args[2];
	e->time = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_ringbuf_submit(e,0);
	return 0;
}


// *** LICENSE *** //
char LICENSE[] SEC("license") = "Dual BSD/GPL";
