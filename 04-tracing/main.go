//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf file_open.c -- -I../headers

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	log.Println("✅ File open tracer loaded")

	// EXERCISE 5: Attach tracepoint to sys_enter_openat
	// Hint: Use link.Tracepoint with category "syscalls" and name "sys_enter_openat"
	tpLink, err := /* YOUR CODE HERE */
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tpLink.Close()
	log.Println("✅ Tracepoint attached: syscalls/sys_enter_openat")

	log.Println("\n📡 Tracking file opens per process")
	log.Println("💡 Generate activity in Terminal 2: ls /tmp, cat /etc/hostname, find /etc -name '*.conf'")
	log.Println()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			log.Println("\n🛑 Shutting down...")
			return
		case <-ticker.C:
			printStats(&objs)
		}
	}
}

func printStats(objs *bpfObjects) {
	var pid uint32
	var count uint64

	log.Println("📊 File opens by process:")
	log.Println("PID     | Opens | Command")
	log.Println("--------|-------|------------------")

	// EXERCISE 6: Iterate over the open_counts map
	// Hint: Use objs.OpenCounts.Iterate()
	iter := /* YOUR CODE HERE */
	total := uint64(0)
	entries := 0

	for iter.Next(&pid, &count) {
		// Get process name
		comm := getProcessName(pid)

		// Filter out system noise
		if strings.Contains(comm, "systemd") {
			continue
		}

		log.Printf("%-7d | %-5d | %s", pid, count, comm)
		total += count
		entries++

		if entries >= 10 {
			break // Show top 10
		}
	}

	if err := iter.Err(); err != nil {
		log.Printf("❌ Iterator error: %v", err)
	}

	if entries == 0 {
		log.Println("(no file opens yet)")
	} else {
		log.Printf("\n📈 Total: %d opens from %d processes\n", total, entries)
	}
}

func getProcessName(pid uint32) string {
	// Try to read /proc/PID/comm
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		// Process may have exited
		return "(exited)"
	}
	return strings.TrimSpace(string(data))
}
