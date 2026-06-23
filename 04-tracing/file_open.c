//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

struct file_open_event {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	char filename[FILENAME_LEN];
	int flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint version - Stable ABI, recommended for production
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_tracepoint(struct trace_event_raw_sys_enter *ctx) {
	struct file_open_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	// EXERCISE 1: Extract PID from current task
	// Hint: Use bpf_get_current_pid_tgid() and shift right by 32 bits
	event->pid = /* YOUR CODE HERE */;

	// EXERCISE 2: Get process name (comm)
	// Hint: Use bpf_get_current_comm with event->comm and sizeof
	/* YOUR CODE HERE */

	// EXERCISE 3: Read filename from userspace
	// Tracepoint args: ctx->args[1] is the filename pointer (const char __user *)
	// Hint: Use bpf_probe_read_user_str(dest, size, src)
	bpf_probe_read_user_str(/* YOUR CODE HERE */);

	// EXERCISE 4: Read flags from tracepoint args
	// Tracepoint args: ctx->args[2] contains the flags as integer
	event->flags = /* YOUR CODE HERE */;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

// Kprobe version - Works on any kernel but less stable
// Note: do_sys_openat2 is the internal kernel function for openat
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_openat_kprobe, int dfd, const char __user *filename, struct open_how *how) {
	struct file_open_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// EXERCISE 5: Read filename parameter from kernel function
	// The filename is already a parameter (const char __user *filename)
	// Hint: Use bpf_probe_read_user_str to read from the filename pointer
	bpf_probe_read_user_str(/* YOUR CODE HERE */);

	// EXERCISE 6: Extract flags from open_how struct
	// The 'how' parameter contains a 'flags' field
	// Hint: Use BPF_CORE_READ to safely read how->flags
	BPF_CORE_READ_INTO(&event->flags, /* YOUR CODE HERE */);

	bpf_ringbuf_submit(event, 0);
	return 0;
}
