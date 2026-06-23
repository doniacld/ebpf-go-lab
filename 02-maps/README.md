# Example 02: Maps & Data Structures

Learn how to work with eBPF maps from Go: hash maps, configuration, and ring buffers.

## What This Example Does

- **Hash Map**: Count execve calls per PID
- **Configuration Map**: Control eBPF program behavior from Go
- **Ring Buffer**: Stream events to userspace in real-time
- **Map Iteration**: Read all hash map entries

## Running

```bash
go generate
go run -exec sudo .
```

## Expected Output

```
✅ eBPF program loaded
✅ Configuration updated: enabled=true, min_pid=1000
✅ Kprobe attached
📡 Listening for events (Ctrl+C to exit)...
🎯 Event: PID=12345, Comm=bash
🎯 Event: PID=12346, Comm=ls

📊 Hash Map Stats (PID → Count):
  PID 12345: 3 executions
  PID 12346: 1 executions
```

## Key Concepts

### Hash Maps
```go
// Read single entry
var count uint64
err := objs.PidCounts.Lookup(&pid, &count)

// Iterate all entries
iter := objs.PidCounts.Iterate()
for iter.Next(&key, &value) {
    fmt.Printf("PID %d: %d\n", key, value)
}
```

### Configuration Maps
```go
// Write configuration
cfg := bpfConfig{Enabled: 1, MinPid: 1000}
objs.ConfigMap.Update(&key, &cfg, 0)
```

### Ring Buffers
```go
// Open reader
rd, _ := ringbuf.NewReader(objs.Events)

// Read events
record, _ := rd.Read()
binary.Read(bytes.NewReader(record.RawSample), 
            binary.LittleEndian, &event)
```

## What to Try

1. Change `MinPid` to 0 to track all processes
2. Generate activity: `ls`, `ps aux`, `find /tmp`
3. Watch both ring buffer events AND map stats
4. Stop program, restart - hash map is empty (not pinned)
