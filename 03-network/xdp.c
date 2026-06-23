//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Ethernet header
struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
	__u8 ihl : 4;
	__u8 version : 4;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));

#define ETH_P_IP 0x0800

// LRU Hash map: Count packets by source IP
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);   // Source IP
	__type(value, __u64); // Packet count
	__uint(max_entries, 1024);
} packet_counts SEC(".maps");

SEC("xdp")
int xdp_count_packets(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// Parse Ethernet header
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	// Only process IPv4
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	// Parse IP header
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}

	// Count by source IP
	__u32 src_ip = ip->saddr;
	__u64 *count = bpf_map_lookup_elem(&packet_counts, &src_ip);

	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 init_val = 1;
		bpf_map_update_elem(&packet_counts, &src_ip, &init_val, BPF_ANY);
	}

	return XDP_PASS;
}
