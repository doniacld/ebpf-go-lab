//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf hash_map.c -- -I../../headers

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	// Load eBPF objects (maps + programs)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	log.Println("✅ eBPF program loaded")

	// Attach kprobe to sys_execve
	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %v", err)
	}
	defer kp.Close()
	log.Println("✅ Kprobe attached to sys_execve")
	log.Println()

	// EXERCISE 1: Add code here to insert a test entry (PID 1 → count 99)

	// EXERCISE 2: Add code here to lookup PID 1

	log.Println("📊 Monitoring executions (Ctrl+C to exit)...")
	log.Println("   Run commands in Terminal 2 to generate activity!")
	log.Println()

	// Periodically read hash map
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for i := 0; i < 5; i++ {
		<-ticker.C
		log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Println("📊 Hash Map Contents (PID → Count):")

		var (
			key   uint32
			value uint64
		)

		// OPERATION: Iterate over all entries in the map
		iter := objs.PidCounts.Iterate()
		count := 0
		for iter.Next(&key, &value) {
			log.Printf("  PID %d: %d executions", key, value)
			count++

			// EXERCISE 3: Add code here to delete PIDs with count == 1
		}

		if iter.Err() != nil {
			log.Printf("❌ Error iterating map: %v", iter.Err())
		}

		if count == 0 {
			log.Println("  (empty)")
		} else {
			log.Printf("\n  Total: %d PIDs tracked", count)
		}
	}

	log.Println("\n✅ Done!")
}
