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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: sudo go run . <tracepoint|kprobe>")
	}

	hookType := os.Args[1]

	// EXERCISE 1: Load eBPF objects
	// Hint: Create bpfObjects{}, call loadBpfObjects, defer Close
	objs := /* YOUR CODE HERE */
	if err := loadBpfObjects(/* YOUR CODE HERE */); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	log.Println("✅ eBPF program loaded")

	// EXERCISE 2: Attach based on hook type
	var l link.Link
	var err error

	switch hookType {
	case "tracepoint":
		// EXERCISE 3: Attach tracepoint
		// Hint: link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenatTracepoint, nil)
		l, err = link.Tracepoint(/* YOUR CODE HERE */)
		log.Println("🔗 Using TRACEPOINT (stable syscall tracing)")

	case "kprobe":
		// EXERCISE 4: Attach kprobe
		// Hint: link.Kprobe("do_sys_openat2", objs.TraceOpenatKprobe, nil)
		l, err = link.Kprobe(/* YOUR CODE HERE */)
		log.Println("🔗 Using KPROBE (kernel function hook)")

	default:
		log.Fatalf("Unknown hook type: %s (use: tracepoint or kprobe)", hookType)
	}

	if err != nil {
		log.Fatalf("attaching %s: %v", hookType, err)
	}
	defer l.Close()

	log.Printf("✅ Attached %s", hookType)

	// EXERCISE 5: Create ring buffer reader
	// Hint: ringbuf.NewReader(objs.Events)
	rd, err := ringbuf.NewReader(/* YOUR CODE HERE */)
	if err != nil {
		log.Fatalf("opening ringbuf: %v", err)
	}
	defer rd.Close()

	log.Println("📂 Tracing file opens (Ctrl+C to exit)...")
	log.Println("💡 Tip: Run 'cat /etc/hostname' or 'ls /tmp' in another terminal\n")

	// EXERCISE 6: Read events from ring buffer
	for {
		// Read one event
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ring buffer closed")
				return
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		// EXERCISE 7: Parse event from raw bytes
		// Hint: Use binary.Read with bytes.NewReader(record.RawSample), binary.LittleEndian, &event
		var event bpfFileOpenEvent
		if err := binary.Read(/* YOUR CODE HERE */); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		// Format and print
		comm := unix.ByteSliceToString(event.Comm[:])
		filename := unix.ByteSliceToString(event.Filename[:])

		// EXERCISE 8: Format flags as hex
		// Print: "📂 PID=<pid> (<comm>) opened: <filename> (flags: 0x<hex>)"
		fmt.Printf("📂 PID=%d (%s) opened: %s (flags: %s)\n",
			event.Pid, comm, filename, /* YOUR CODE HERE - format flags as 0x%x */)
	}
}
