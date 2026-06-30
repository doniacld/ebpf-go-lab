//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf xdp_histogram.c -- -I../../headers

package main

import (
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: sudo go run . <interface>")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface %s: %v", ifaceName, err)
	}

	// Load eBPF program
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	log.Println("✅ eBPF program loaded")

	// EXERCISE 3: Attach XDP program to interface
	// Hint: Use link.AttachXDP with link.XDPOptions
	// Set Program and Interface fields.
	// Also set Flags: link.XDPGenericMode — generic (SKB) mode works on
	// loopback and virtual NICs, which don't support native-mode XDP.
	/* YOUR CODE HERE */

	log.Printf("✅ XDP attached to %s", ifaceName)
	log.Println("📊 Packet Size Histogram (Ctrl+C to exit)")
	log.Println()

	// Display histogram every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	bucketNames := []string{
		"Control   (<=100)",
		"Small     (101-200)",
		"Medium    (201-500)",
		"Large     (501-1000)",
		"MTU-sized (>1000)",
	}

	for range ticker.C {
		log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		var total uint64
		for i := uint32(0); i < 5; i++ {
			var count uint64
			// EXERCISE 4: Read count from histogram map
			// Hint: Use objs.SizeHistogram.Lookup(&i, &count)
			/* YOUR CODE HERE */

			total += count

			// Draw ASCII bar
			bar := strings.Repeat("█", int(count/10))
			if count > 0 && len(bar) == 0 {
				bar = "▏"
			}
			log.Printf("%-18s: %s %d", bucketNames[i], bar, count)
		}

		log.Printf("\n📦 Total packets: %d\n", total)
	}
}
