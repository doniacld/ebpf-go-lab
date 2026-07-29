//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// MAP DEFINITION: Define an eBPF map to store our execution counter
// This map is shared between the kernel (eBPF program) and userspace (Go program)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);  // Array map: indexed access like array[0]
	__type(key, __u32);                 // Key type: uint32 (the index)
	__type(value, __u64);               // Value type: uint64 (the counter value)
	__uint(max_entries, 1);             // Size: 1 entry (we only need one counter)
} exec_count SEC(".maps");              // Map name: exec_count

// KPROBE PROGRAM: Trace program executions
// This program attaches to the sys_execve kernel function
// It runs every time any process calls execve() to execute a new program
SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	__u32 key = 0;  // Array index 0 (our only entry)

	// Look up the counter in our map
	__u64 *count = bpf_map_lookup_elem(&exec_count, &key);

	if (count) {
		// Atomically increment the counter (thread-safe)
		__sync_fetch_and_add(count, 1);
	}

	return 0;  // Return 0 = success
}
