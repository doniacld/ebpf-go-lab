# eBPF + Go Lab Exercises

Hands-on exercises for learning eBPF programming with Go and the cilium/ebpf library.

## Structure

```
01-lifecycle/          Demo: eBPF program lifecycle (load, attach, read)
02-maps/              Exercises: Hash maps, array maps, ring buffers
03-network/           Exercises: XDP packet filtering, TC traffic control
04-tracing/           Exercises: Tracepoints for system call monitoring
07-exam/              Final exam: Build a process activity monitor
headers/              Shared eBPF headers (helper functions, macros)
```

## Prerequisites

- Go 1.21+
- Linux kernel 5.10+ with BTF enabled
- clang 11+
- llvm

Install dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm golang

# Fedora/RHEL
sudo dnf install clang llvm golang
```

## Quick Start

Each exercise directory contains:
- `*.c` - eBPF kernel programs (with EXERCISE markers)
- `main.go` - Go userspace loader (with EXERCISE markers)
- `go.mod` - Go dependencies

**Workflow:**
```bash
cd 02-maps/01-hash-map
go get github.com/cilium/ebpf/cmd/bpf2go  # Get bpf2go tool
go generate                                 # Compile C → generate Go bindings
sudo go run .                               # Run (needs sudo for eBPF)
```

## What You'll Learn

- **Maps**: Store and share data between kernel and userspace
- **Network Hooks**: Intercept packets with XDP and TC
- **Tracing**: Monitor system calls with tracepoints
- **bpf2go**: Generate type-safe Go bindings from C code

## Resources

- [eBPF Go Library Docs](https://ebpf-go.dev/)
- [Cilium eBPF Examples](https://github.com/cilium/ebpf/tree/main/examples)
- [eBPF.io Learning Resources](https://ebpf.io/what-is-ebpf)

## License

Educational use - part of Isovalent eBPF training labs.
