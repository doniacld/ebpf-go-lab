# Example 01: Program Lifecycle

Learn how to load, attach, and manage eBPF programs from Go.

## What This Example Does

- Compiles C code to eBPF bytecode using bpf2go
- Loads eBPF program into the kernel
- Attaches a kprobe to `sys_execve` (traces program executions)
- Reads counters from an eBPF map
- Demonstrates graceful cleanup with `defer`

## Running

```bash
# Generate Go code from C
go generate

# Run (requires root for eBPF operations)
go run -exec sudo .
```

## Expected Output

```
✅ eBPF program loaded
✅ Kprobe attached to sys_execve
Counting execve syscalls. Press Ctrl+C to exit.
📊 Executions: 0
📊 Executions: 3
📊 Executions: 7
...
```

## What to Try

In another terminal, run commands to trigger execve:
```bash
ls
ps aux
echo "hello"
```

Watch the counter increment!

## Key Concepts

- **bpf2go**: The `//go:generate` directive compiles C → generates Go structs
- **LoadCollection**: Loads all programs and maps from the compiled object
- **link.Kprobe**: Attaches to kernel function dynamically
- **defer Close()**: Ensures cleanup even if program exits early
- **Map Lookup**: Type-safe access to eBPF maps from Go
