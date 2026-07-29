//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct mac_info {
	__u64 packet_count;   // how many packets carried this MAC
	__u64 first_seen_ns;  // bpf_ktime_get_ns() at first sighting
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);  // the 6-byte MAC packed into a u64 (see mac_to_u64)
	__type(value, struct mac_info);
	__uint(max_entries, 256);
} mac_tracker SEC(".maps");

// 6 bytes is awkward as a map key, so pack it into one u64.
// main.go reverses this with u64ToMac().
static __always_inline __u64 mac_to_u64(unsigned char *mac) {
	return ((__u64)mac[0] << 40) |
	       ((__u64)mac[1] << 32) |
	       ((__u64)mac[2] << 24) |
	       ((__u64)mac[3] << 16) |
	       ((__u64)mac[4] << 8)  |
	       ((__u64)mac[5]);
}

// Runs after the driver hands the packet up the stack. On ingress the source
// MAC is whoever sent to us.
SEC("tc/ingress")
int track_ingress_macs(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	// EXERCISE 1: point eth at the start of the packet.
	// Hint: cast `data` to a struct ethhdr pointer.
	struct ethhdr *eth = /* YOUR CODE HERE */;

	// The verifier rejects reads past data_end, so this check is mandatory.
	if (/* YOUR CODE HERE - check if eth + 1 exceeds data_end */) {
		return TC_ACT_OK;
	}

	// EXERCISE 2: pack the SOURCE MAC into the map key.
	// Hint: mac_to_u64() with eth->h_source. See the egress program below,
	// which does the same with eth->h_dest.
	__u64 mac_key = /* YOUR CODE HERE */;

	struct mac_info *info = bpf_map_lookup_elem(&mac_tracker, &mac_key);
	if (info) {
		// Atomic: other CPUs can hit this entry at the same time.
		__sync_fetch_and_add(&info->packet_count, 1);
	} else {
		// EXERCISE 3: first sighting, so fill in the initial entry.
		// Hint: one packet so far, and bpf_ktime_get_ns() for the timestamp.
		struct mac_info new_info = {
			.packet_count = /* YOUR CODE HERE */,
			.first_seen_ns = /* YOUR CODE HERE */,
		};
		bpf_map_update_elem(&mac_tracker, &mac_key, &new_info, BPF_ANY);
	}

	return TC_ACT_OK;
}

// Runs at the end of transmit processing, just before the driver. Same shape as
// ingress, but keyed on the destination MAC. Written out in full as a reference
// for the ingress exercises above.
SEC("tc/egress")
int track_egress_macs(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = (struct ethhdr *)data;
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK;
	}

	// Egress mirrors ingress but keys on the destination MAC (eth->h_dest).
	__u64 mac_key = mac_to_u64(eth->h_dest);

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
