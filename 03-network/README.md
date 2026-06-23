# Example 03: Network Hooks (XDP)

Learn how to attach XDP programs to network interfaces and process packets.

## What This Example Does

- Attaches XDP program to a network interface
- Parses Ethernet and IPv4 headers
- Counts packets by source IP address
- Uses LRU hash map (auto-evicts old entries)

## Running

```bash
go generate
go run -exec sudo . lo  # Use loopback interface
```

## Expected Output

```
✅ eBPF program loaded
✅ XDP program attached to lo
📡 Counting packets by source IP (Ctrl+C to exit)...

📊 Packet Counts by Source IP:
  127.0.0.1: 45 packets

📊 Packet Counts by Source IP:
  127.0.0.1: 78 packets
```

## Generate Traffic

In another terminal:
```bash
# Generate loopback traffic
curl http://localhost:80
ping -c 10 127.0.0.1
wget http://localhost:8080
```

## Key Concepts

### XDP Attachment
```go
iface, _ := net.InterfaceByName("eth0")
link.AttachXDP(link.XDPOptions{
    Program:   objs.XdpCountPackets,
    Interface: iface.Index,
})
```

### Network Byte Order
IP addresses in packets are in network byte order (little-endian on x86):
```go
func intToIP(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
```

### LRU Hash Map
Automatically evicts least-recently-used entries when full:
```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
} packet_counts SEC(".maps");
```

## What to Try

1. Attach to different interfaces: `eth0`, `wlan0`
2. Generate traffic from different sources
3. Watch the LRU map auto-evict old IPs when it fills
4. Modify C code to count by destination IP instead
