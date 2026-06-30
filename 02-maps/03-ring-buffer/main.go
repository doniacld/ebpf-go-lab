//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type event bpf ring_buffer.c -- -I../../headers

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	log.Println("✅ eBPF program loaded")

	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %v", err)
	}
	defer kp.Close()
	log.Println("✅ Kprobe attached to sys_execve")
	log.Println("📡 Listening for events in real-time (Ctrl+C to exit)...")
	log.Println()

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf: %v", err)
	}
	defer rd.Close()

	// Handle Ctrl+C gracefully
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		log.Println("\n\n✅ Shutting down...")
		rd.Close()
	}()

	// Read events in real-time (blocks until event arrives)
	eventCount := 0
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		// Parse binary event data (little-endian)
		var event bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample),
			binary.LittleEndian, &event); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		eventCount++
		log.Printf("🎯 Event #%d: PID=%d, Comm=%s", eventCount, event.Pid, comm(event.Comm)) // EXERCISE: also print event.Timestamp
	}

	log.Printf("\n📊 Total events received: %d", eventCount)
}

// comm converts the fixed-size C "char comm[16]" field (a [16]int8) into a
// Go string, stopping at the first null terminator.
func comm(raw [16]int8) string {
	b := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
