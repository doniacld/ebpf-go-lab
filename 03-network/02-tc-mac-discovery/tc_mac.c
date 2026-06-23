//go:build ignore

#include "../../headers/common.h"
#include "../../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct mac_info {
	__u64 packet_count;
	__u64 first_seen_ns;
};

// Track unique MAC addresses
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);  // MAC address as 64-bit int
	__type(value, struct mac_info);
	__uint(max_entries, 256);
} mac_tracker SEC(".maps");

// Helper: Convert 6-byte MAC to uint64 for use as map key
static __always_inline __u64 mac_to_u64(unsigned char *mac) {
	return ((__u64)mac[0] << 40) |
	       ((__u64)mac[1] << 32) |
	       ((__u64)mac[2] << 24) |
	       ((__u64)mac[3] << 16) |
	       ((__u64)mac[4] << 8)  |
	       ((__u64)mac[5]);
}

SEC("tc/ingress")
int track_ingress_macs(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	// EXERCISE 1: Parse Ethernet header
	// Hint: Cast data to struct ethhdr pointer
	// Check bounds: (void *)(eth + 1) > data_end
	struct ethhdr *eth = /* YOUR CODE HERE */;

	// Bounds check
	if (/* YOUR CODE HERE - check if eth + 1 exceeds data_end */) {
		return TC_ACT_OK;
	}

	// EXERCISE 2: Extract source MAC address
	// Hint: Use mac_to_u64() helper with eth->h_source
	__u64 mac_key = /* YOUR CODE HERE */;

	// Lookup existing entry
	struct mac_info *info = bpf_map_lookup_elem(&mac_tracker, &mac_key);
	if (info) {
		// MAC already seen - increment counter
		__sync_fetch_and_add(&info->packet_count, 1);
	} else {
		// EXERCISE 3: New MAC - create initial entry
		// Set packet_count = 1
		// Set first_seen_ns = bpf_ktime_get_ns()
		struct mac_info new_info = {
			.packet_count = /* YOUR CODE HERE */,
			.first_seen_ns = /* YOUR CODE HERE */,
		};
		bpf_map_update_elem(&mac_tracker, &mac_key, &new_info, BPF_ANY);
	}

	return TC_ACT_OK;
}

SEC("tc/egress")
int track_egress_macs(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = (struct ethhdr *)data;
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK;
	}

	// EXERCISE 4: Track destination MAC (eth->h_dest)
	// Use same logic as ingress but with h_dest instead of h_source
	__u64 mac_key = /* YOUR CODE HERE */;

	struct mac_info *info = bpf_map_lookup_elem(&mac_tracker, &mac_key);
	if (info) {
		__sync_fetch_and_add(&info->packet_count, 1);
	} else {
		struct mac_info new_info = {
			.packet_count = 1,
			.first_seen_ns = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&mac_tracker, &mac_key, &new_info, BPF_ANY);
	}

	return TC_ACT_OK;
}
