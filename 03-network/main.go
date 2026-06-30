package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf xdp.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <interface>", os.Args[0])
	}
	ifaceName := os.Args[1]

	// Load eBPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	log.Println("✅ eBPF program loaded")

	// Get network interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("getting interface %s: %v", ifaceName, err)
	}

	// Attach XDP program.
	// Generic (SKB) mode works on loopback and virtual NICs, which don't
	// support native-mode XDP. On bare metal with a supporting driver you
	// can omit Flags for native-mode performance.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCountPackets,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attaching XDP: %v", err)
	}
	defer l.Close()

	log.Printf("✅ XDP program attached to %s", ifaceName)
	log.Println("📡 Counting packets by source IP (Ctrl+C to exit)...")

	// Handle graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("\n🛑 Shutting down...")
			return
		case <-ticker.C:
			printStats(&objs)
		}
	}
}

func printStats(objs *bpfObjects) {
	log.Println("\n📊 Packet Counts by Source IP:")

	var (
		key   uint32
		value uint64
	)

	iter := objs.PacketCounts.Iterate()
	count := 0
	for iter.Next(&key, &value) {
		ip := intToIP(key)
		log.Printf("  %s: %d packets", ip, value)
		count++
	}

	if err := iter.Err(); err != nil {
		log.Printf("iterating map: %v", err)
	}

	if count == 0 {
		log.Println("  (no packets yet)")
	}
	log.Println()
}

// Convert uint32 to IP string (network byte order)
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}
