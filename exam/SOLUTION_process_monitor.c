//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Ring buffer for real-time events (already defined for you)
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// TODO 1 SOLUTION: Define hash map for tracking activity
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u64);
} process_activity SEC(".maps");

// Event structure for ring buffer
struct event {
	__u32 pid;
	char comm[16];
	char type; // 'e' for exec, 'o' for open
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
	// TODO 2 SOLUTION: Extract PID from current task
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	// TODO 3 SOLUTION: Update activity count in process_activity map
	__u64 *count = bpf_map_lookup_elem(&process_activity, &pid);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 initial = 1;
		bpf_map_update_elem(&process_activity, &pid, &initial, BPF_ANY);
	}

	// Send event to ring buffer (already implemented)
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	e->type = 'e';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
	// TODO 4 SOLUTION: Extract PID (same as TODO 2)
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	// TODO 5 SOLUTION: Update activity count (same as TODO 3)
	__u64 *count = bpf_map_lookup_elem(&process_activity, &pid);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 initial = 1;
		bpf_map_update_elem(&process_activity, &pid, &initial, BPF_ANY);
	}

	// Send event to ring buffer (already implemented)
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	e->type = 'o';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	return 0;
}
