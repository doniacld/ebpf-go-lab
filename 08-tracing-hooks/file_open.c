//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// PID -> number of file opens. Go iterates this to print the table.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} open_counts SEC(".maps");

// Fires on the way into openat(), before the kernel does the work. Unlike a
// kprobe, this attachment point is part of the kernel ABI and will not move.
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	// EXERCISE 1: get the PID of the calling process.
	// Hint: bpf_get_current_pid_tgid() packs TGID and TID into one u64,
	// with the PID in the upper 32 bits.
	__u32 pid = /* YOUR CODE HERE */;

	// Kernel threads are not interesting here.
	if (pid == 0)
		return 0;

	// EXERCISE 2: look up this PID's current count.
	// Hint: bpf_map_lookup_elem(&open_counts, &pid). Returns NULL if absent.
	__u64 *count = /* YOUR CODE HERE */;

	if (count) {
		// EXERCISE 3: bump the existing count.
		// Hint: __sync_fetch_and_add, since other CPUs may be in here too.
		/* YOUR CODE HERE */
	} else {
		// EXERCISE 4: first open from this PID, so store the initial value.
		// Hint: bpf_map_update_elem with BPF_ANY.
		__u64 init_val = 1;
		/* YOUR CODE HERE */
	}

	return 0;
}
