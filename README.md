# eBPF + Go Lab Exercises

Hands-on exercises for learning eBPF programming with Go and the cilium/ebpf library.

## Structure

One directory per challenge of the Isovalent "Go + eBPF Development" track,
numbered to match the track's challenges exactly:

```
02-program-lifecycle/       Demo: eBPF program lifecycle (load, attach, read)
03-maps-hash-map/           Exercise: Hash map CRUD, count execs per PID
04-maps-array-map/          Exercise: Array maps for config and counters
05-maps-ring-buffer/        Exercise: Stream events to userspace
06-network-xdp-histogram/   Exercise: XDP packet size classification
07-network-tc-mac/          Exercise: TC MAC address discovery
08-tracing-hooks/           Exercise: Tracepoints for syscall monitoring
10-exam/                    Final exam: Build a process activity monitor
headers/                    Shared eBPF headers (helper functions, macros)
```

Challenges 01 (introduction) and 09 (quiz) have no code, hence the gaps.

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
cd 03-maps-hash-map
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
