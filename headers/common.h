/* Common BPF headers - simplified version that works without kernel headers */
#ifndef __COMMON_H__
#define __COMMON_H__

/* Basic type definitions */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

/* BPF section macro */
#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* BPF map types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27

/* BPF helper attribute macros */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* BPF update flags */
#define BPF_ANY 0

/* XDP action codes */
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

/* XDP metadata - packet context */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

/* TC action codes */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/* TC (Traffic Control) metadata - socket buffer context */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__u64 gso_size;
	__u32 tstamp_type;
	__u32 hwtstamp;
};

/* Ethernet header */
struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__u16 h_proto;
} __attribute__((packed));

#endif /* __COMMON_H__ */
