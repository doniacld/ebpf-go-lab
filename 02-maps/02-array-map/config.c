//go:build ignore

#include "../../headers/common.h"
#include "../../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Configuration structure
struct config {
	__u32 enabled;   // Is tracking enabled?
	__u32 min_pid;   // Minimum PID to track
};

// Configuration stored in array map (index 0)
// Use case: Control eBPF program behavior from userspace
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config);
	__uint(max_entries, 1);  // Just one config entry
} config_map SEC(".maps");

// Simple counter stored in array map (index 0)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} exec_count SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	__u32 key = 0;

	// Read configuration from userspace
	struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg || !cfg->enabled) {
		return 0;  // Tracking disabled
	}

	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	// Filter by min_pid from configuration
	if (pid < cfg->min_pid) {
		return 0;  // PID too low, skip
	}

	// Increment counter
	__u64 *count = bpf_map_lookup_elem(&exec_count, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
	}

	return 0;
}
