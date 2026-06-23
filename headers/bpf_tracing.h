/* BPF tracing helpers (fentry, CO-RE) - simplified version */
#ifndef __BPF_TRACING_H__
#define __BPF_TRACING_H__

/* Tracepoint context structure (minimal definition) */
struct trace_event_raw_sys_enter {
	unsigned long long args[6];
};

/* BPF_PROG macro for fentry/fexit programs */
#define BPF_PROG(name, args...) \
	int name(args)

/* BPF_KPROBE macro for kprobe programs */
#define BPF_KPROBE(name, args...) \
	int name(struct pt_regs *ctx, ##args)

/* BPF_KRETPROBE macro for kretprobe programs */
#define BPF_KRETPROBE(name, args...) \
	int name(struct pt_regs *ctx, ##args)

/* CO-RE (Compile Once, Run Everywhere) helpers */
#define BPF_CORE_READ(src, a, ...) ({					\
	___type((src), a, ##__VA_ARGS__) __r;				\
	__builtin_memset(&__r, 0, sizeof(__r));				\
	__r; })

#define BPF_CORE_READ_INTO(dst, src, a, ...) ({			\
	___type((src), a, ##__VA_ARGS__) __r;				\
	__builtin_memset(&__r, 0, sizeof(__r));				\
	*(dst) = __r; })

#define ___type(src, a, ...) __typeof__(((src)->a))

/* Atomic operations for map updates */
#ifndef __sync_fetch_and_add
#define __sync_fetch_and_add(ptr, val) __atomic_fetch_add(ptr, val, __ATOMIC_RELAXED)
#endif

#endif /* __BPF_TRACING_H__ */
