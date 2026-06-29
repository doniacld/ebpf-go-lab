//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Simple counter map: PID -> count of file opens
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} open_counts SEC(".maps");

// Tracepoint version - Stable ABI
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	// EXERCISE 1: Get current PID
	// Hint: Use bpf_get_current_pid_tgid() and shift right by 32 bits
	__u32 pid = /* YOUR CODE HERE */;

	// Skip PID 0 (kernel threads)
	if (pid == 0)
		return 0;

	// EXERCISE 2: Lookup existing counter for this PID
	// Hint: Use bpf_map_lookup_elem with &open_counts and &pid
	__u64 *count = /* YOUR CODE HERE */;

	if (count) {
		// EXERCISE 3: Increment the counter atomically
		// Hint: Use __sync_fetch_and_add
		/* YOUR CODE HERE */
	} else {
		// EXERCISE 4: Initialize a new counter with value 1
		// Hint: Use bpf_map_update_elem with BPF_ANY flag
		__u64 init_val = 1;
		/* YOUR CODE HERE */
	}

	return 0;
}
