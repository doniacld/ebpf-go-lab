//go:build ignore

#include "../../headers/common.h"
#include "../../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Histogram buckets for packet sizes
// Index 0: Control   (<=100 bytes)   - ACK, SYN
// Index 1: Small     (101-200 bytes) - DNS, short HTTP
// Index 2: Medium    (201-500 bytes)
// Index 3: Large     (501-1000 bytes)
// Index 4: MTU-sized (>1000 bytes)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 5);
} size_histogram SEC(".maps");

SEC("xdp")
int packet_histogram(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// EXERCISE 1: Calculate packet size
	// Hint: Subtract data pointer from data_end pointer
	__u32 pkt_size = /* YOUR CODE HERE */;

	// EXERCISE 2: Determine which bucket based on size
	// Use if/else to classify:
	// 0-64 → bucket 0
	// 65-512 → bucket 1
	// 513-1024 → bucket 2
	// 1025-1500 → bucket 3
	// >1500 → bucket 4
	__u32 bucket;
	/* YOUR CODE HERE */

	// Update the histogram counter for this bucket
	__u64 *count = bpf_map_lookup_elem(&size_histogram, &bucket);
	if (count) {
		__sync_fetch_and_add(count, 1);
	}

	return XDP_PASS;
}
