//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Hash map: Count events by PID
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);   // PID
	__type(value, __u64); // Count
	__uint(max_entries, 1024);
} pid_counts SEC(".maps");

// Configuration map: Control program behavior
struct config {
	__u32 enabled;
	__u32 min_pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config);
	__uint(max_entries, 1);
} config_map SEC(".maps");

// Ring buffer: Stream events to userspace
struct event {
	__u32 pid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	// Check configuration
	__u32 cfg_key = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
	if (!cfg || !cfg->enabled) {
		return 0;
	}

	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	// Filter by min PID
	if (pid < cfg->min_pid) {
		return 0;
	}

	// Update hash map counter
	__u64 *count = bpf_map_lookup_elem(&pid_counts, &pid);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 init_val = 1;
		bpf_map_update_elem(&pid_counts, &pid, &init_val, BPF_ANY);
	}

	// Push event to ring buffer
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	return 0;
}
