//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// TODO 1: Define hash map for tracking activity
// Name: process_activity
// Key: __u32 (PID)
// Value: __u64 (activity count)
// Max entries: 256
//
// Hint: Use BPF_MAP_TYPE_HASH
// Hint: Check Challenge 03 (Maps) for hash map definition pattern

/* YOUR CODE HERE */

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
	// TODO 2: Extract PID from current task
	// Hint: Use bpf_get_current_pid_tgid() >> 32

	__u32 pid = /* YOUR CODE HERE */;

	// TODO 3: Update activity count in process_activity map
	// Steps:
	// 1. Lookup existing count: bpf_map_lookup_elem(&process_activity, &pid)
	// 2. If found: increment with __sync_fetch_and_add(count, 1)
	// 3. If not found: initialize to 1 with bpf_map_update_elem()
	//
	// Hint: Check Challenge 03 hash map example for the exact pattern

	/* YOUR CODE HERE */

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
	// TODO 4: Extract PID (same as TODO 2)

	__u32 pid = /* YOUR CODE HERE */;

	// TODO 5: Update activity count (same as TODO 3)

	/* YOUR CODE HERE */

	return 0;
}
