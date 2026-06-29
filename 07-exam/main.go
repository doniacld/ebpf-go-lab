//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf process_monitor.c -- -I../headers

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	// Load eBPF objects (already implemented)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	log.Println("✅ eBPF programs loaded")

	// TODO 1: Attach sys_enter_execve tracepoint
	// Hint: link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExec, nil)
	// Store result in variable 'execLink'

	execLink, err := /* YOUR CODE HERE */
	if err != nil {
		log.Fatalf("attaching execve tracepoint: %v", err)
	}
	defer execLink.Close()
	log.Println("✅ Tracepoint attached: sys_enter_execve")

	// TODO 2: Attach sys_enter_openat tracepoint
	// Hint: link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpen, nil)
	// Store result in variable 'openLink'

	openLink, err := /* YOUR CODE HERE */
	if err != nil {
		log.Fatalf("attaching openat tracepoint: %v", err)
	}
	defer openLink.Close()
	log.Println("✅ Tracepoint attached: sys_enter_openat")

	log.Println("📊 Monitoring process activity (Ctrl+C to exit)")
	log.Println("💡 Generate activity in Terminal 2: ls /tmp, cat /etc/hostname, ps aux")
	log.Println()

	// Graceful shutdown (already implemented)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Statistics ticker (already implemented)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Print header once
	fmt.Println("PID     | Activity Count | Change")
	fmt.Println("--------|----------------|-------")

	lastCounts := make(map[uint32]uint64)

	// Main loop
	for {
		select {
		case <-sig:
			fmt.Println("\n🛑 Shutting down...")
			return
		case <-ticker.C:
			printStats(&objs, lastCounts)
		}
	}
}

func printStats(objs *bpfObjects, lastCounts map[uint32]uint64) {
	var pid uint32
	var count uint64
	var total uint64
	hasChanges := false

	// TODO 3: Create iterator for process_activity map
	// Hint: objs.ProcessActivity.Iterate()

	iter := /* YOUR CODE HERE */

	// TODO 4: Iterate through map entries
	// Hint: for iter.Next(&pid, &count) { ... }

	for /* YOUR CODE HERE */ {
		total += count

		// Calculate change since last check
		last := lastCounts[pid]
		if count != last {
			change := count - last
			fmt.Printf("%-7d | %-14d | +%d\n", pid, count, change)
			lastCounts[pid] = count
			hasChanges = true
		}
	}

	if iter.Err() != nil {
		log.Printf("Error: %v", iter.Err())
	}

	if !hasChanges {
		fmt.Print(".")  // Show progress indicator
	} else {
		fmt.Printf("Total: %d events\n", total)
	}
}
