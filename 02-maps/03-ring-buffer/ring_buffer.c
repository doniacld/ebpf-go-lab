//go:build ignore

#include "../../headers/common.h"
#include "../../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Forward declaration for kprobe context
struct pt_regs;

// Time helper (not in headers)
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;

// Event structure - data sent to userspace
struct event {
	__u32 pid;
	char comm[16];  // Process name
	// EXERCISE: Add a __u64 timestamp field here
};

// Force struct event into BTF for bpf2go -type flag
const struct event *__event_type_hint __attribute__((unused));

// Ring buffer for streaming events to userspace
// Use case: Real-time event notifications (no polling needed)
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);  // 256 KB buffer
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	struct event *e;

	// Reserve space in ring buffer
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;  // Buffer full, drop event
	}

	// Fill event data
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// EXERCISE: Capture timestamp using bpf_ktime_get_ns()

	// Submit event to userspace
	bpf_ringbuf_submit(e, 0);

	return 0;
}
