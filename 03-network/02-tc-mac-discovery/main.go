//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type mac_info bpf tc_mac.c -- -I../../headers

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Find the primary network interface (eth0 on most systems, ens4 on GCP).
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		iface, err = net.InterfaceByName("ens4")
		if err != nil {
			log.Fatalf("finding interface (tried eth0, ens4): %v", err)
		}
	}
	ifaceName := iface.Name

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	log.Println("✅ eBPF program loaded")

	// EXERCISE 5: Attach TCX ingress program
	// Hint: Use link.AttachTCX with link.TCXOptions
	// Set Interface, Program, and Attach fields
	// Attach should be ebpf.AttachTCXIngress
	linkIngress, err := /* YOUR CODE HERE */
	if err != nil {
		log.Fatalf("attach ingress: %v", err)
	}
	defer linkIngress.Close()
	log.Printf("✅ TC attached to %s (ingress)", ifaceName)

	// EXERCISE 6: Attach TCX egress program
	// Same as above but with objs.TrackEgressMacs and ebpf.AttachTCXEgress
	linkEgress, err := /* YOUR CODE HERE */
	if err != nil {
		log.Fatalf("attach egress: %v", err)
	}
	defer linkEgress.Close()
	log.Printf("✅ TC attached to %s (egress)", ifaceName)

	log.Println("\n🔍 Discovering MAC addresses (Ctrl+C to exit)...")
	log.Println("💡 Tip: Run 'ping 8.8.8.8' or 'curl google.com' in Terminal 2\n")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	for range ticker.C {
		log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Println("🌐 Discovered MAC Addresses:")

		var macKey uint64
		var info bpfMacInfo

		// EXERCISE 7: Iterate through mac_tracker map
		iter := /* YOUR CODE HERE */
		count := 0

		for iter.Next(&macKey, &info) {
			// EXERCISE 8: Convert uint64 MAC key back to readable format
			// Hint: Use the u64ToMac() helper function below
			macStr := /* YOUR CODE HERE */

			// Calculate how long ago first seen
			firstSeenNs := info.FirstSeenNs
			elapsedNs := time.Since(startTime).Nanoseconds()
			ageSeconds := (elapsedNs - int64(firstSeenNs)) / 1e9

			// Check for broadcast MAC
			suffix := ""
			if macKey == 0xffffffffffff {
				suffix = " (broadcast)"
			}

			log.Printf("  %s → %6d packets (first seen: %ds ago)%s",
				macStr, info.PacketCount, ageSeconds, suffix)
			count++
		}

		if iter.Err() != nil {
			log.Printf("Error iterating: %v", iter.Err())
		}

		if count == 0 {
			log.Println("  (no MACs discovered yet - generate some traffic!)")
		} else {
			log.Printf("\n📊 Total unique MACs: %d\n", count)
		}
	}
}

// Helper: Convert uint64 back to MAC address string
func u64ToMac(mac uint64) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		byte(mac>>40), byte(mac>>32), byte(mac>>24),
		byte(mac>>16), byte(mac>>8), byte(mac))
}
