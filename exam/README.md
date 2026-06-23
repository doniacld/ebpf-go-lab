# Exam: Process Activity Monitor

Complete the incomplete eBPF program to track process activity.

## Prerequisites

**IMPORTANT**: You must have `llvm-strip` available for `go generate` to work. This is automatically installed on Instruqt, but for local testing:

### macOS
```bash
# Install LLVM (includes llvm-strip)
brew install llvm

# Add to PATH if not already there
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"  # ARM Mac
# OR
export PATH="/usr/local/opt/llvm/bin:$PATH"     # Intel Mac
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install -y llvm clang libbpf-dev
```

### Lima VM
```bash
# Install LLVM
sudo apt-get update
sudo apt-get install -y llvm clang

# OR create symlink as workaround
sudo ln -sf /usr/bin/strip /usr/bin/llvm-strip
```

## Your Task

Complete **9 TODOs** across 2 files:

### File 1: `process_monitor.c` (5 TODOs)
- Define hash map
- Extract PIDs
- Update activity counts

### File 2: `main.go` (4 TODOs)
- Attach tracepoints
- Iterate map

## Build & Test

```bash
# Generate eBPF bytecode and build
go generate
go build -o process_monitor .

# Run (requires sudo)
sudo ./process_monitor

# In another terminal, generate activity
ls /tmp
cat /etc/hostname
ps aux
```

## Expected Output

```
✅ eBPF programs loaded
✅ Tracepoint attached: sys_enter_execve
✅ Tracepoint attached: sys_enter_openat
📊 Monitoring process activity (Ctrl+C to exit)

⚡ [exec] PID 1234: bash
⚡ [open] PID 1234: ls
⚡ [open] PID 1234: ls

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Process Activity Statistics

  PID  1234: 8 activities
  PID  5678: 3 activities

📈 Total activity: 11 events
```

## Troubleshooting

### Error: `llvm-strip not found`
```bash
# Install llvm OR create symlink
sudo ln -s /usr/bin/strip /usr/bin/llvm-strip
```

### Error: `asm/types.h not found`
The simplified headers should avoid this. If you still see it:
```bash
# Linux
sudo apt-get install -y linux-headers-$(uname -r)
```

### Error: Cannot find `bpf_map_lookup_elem`
Make sure you're including `../headers/bpf_helpers.h`
