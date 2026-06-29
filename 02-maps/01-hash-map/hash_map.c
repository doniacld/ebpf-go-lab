//go:build ignore

#include "../../headers/common.h"
#include "../../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Hash map: Count executions by PID
// Use case: Track how many times each process executed
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);         // PID
	__type(value, __u64);       // Execution count
	__uint(max_entries, 1024);  // Max 1024 PIDs tracked
} pid_counts SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	// Try to lookup existing count
	__u64 *count = bpf_map_lookup_elem(&pid_counts, &pid);
	if (count) {
		// PID exists - increment counter
		__sync_fetch_and_add(count, 1);
	} else {
		/* PID doesn't exist - initialize with 1 */
		__u64 init_val = 1;
		bpf_map_update_elem(&pid_counts, &pid, &init_val, BPF_ANY);
	}

	return 0;
}
