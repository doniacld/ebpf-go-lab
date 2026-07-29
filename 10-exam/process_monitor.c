//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// TODO 1: Define a hash map named process_activity, keyed by PID (__u32) with
// an activity count (__u64), holding 256 entries. The shape is:
//
//   struct {
//       __uint(type, BPF_MAP_TYPE_HASH);
//       __type(key, ...);
//       __type(value, ...);
//       __uint(max_entries, ...);
//   } my_map SEC(".maps");
//
// Hint: You wrote one in 03-maps-hash-map/hash_map.c.

/* YOUR CODE HERE */

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
	// TODO 2: Extract PID from current task
	// Hint: Use bpf_get_current_pid_tgid() >> 32

	__u32 pid = /* YOUR CODE HERE */;

	// TODO 3: Update this PID's count in process_activity: look it up,
	// increment it if present, initialize it to 1 if not.
	//
	// Hint: You wrote this same pattern in 08-tracing-hooks/file_open.c.

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
