/* BPF helper function declarations */
#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

/* Map operations */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

/* Ring buffer */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;

/* Kprobe/tracing helpers */
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;

/* Network helpers */
static __u16 (*bpf_ntohs)(__u16 val) = (void *) 9;
static __u16 (*bpf_htons)(__u16 val) = (void *) 8;

#endif /* __BPF_HELPERS_H__ */
