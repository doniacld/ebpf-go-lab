package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type config -type event bpf maps.c -- -I../../headers

func main() {
	// Load eBPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	log.Println("✅ eBPF program loaded")

	// Configure program behavior via map
	cfg := bpfConfig{
		Enabled: 1,
		MinPid:  1000, // Only track PIDs >= 1000
	}
	key := uint32(0)
	if err := objs.ConfigMap.Update(&key, &cfg, 0); err != nil {
		log.Fatalf("updating config: %v", err)
	}

	log.Println("✅ Configuration updated: enabled=true, min_pid=1000")

	// Attach kprobe
	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %v", err)
	}
	defer kp.Close()

	log.Println("✅ Kprobe attached")

	// Start reading from ring buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Println("📡 Listening for events (Ctrl+C to exit)...")

	// Handle graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start map stats printer
	go printMapStats(ctx, &objs)

	// Read events from ring buffer
	for {
		select {
		case <-ctx.Done():
			log.Println("\n🛑 Shutting down...")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		var event bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		log.Printf("🎯 Event: PID=%d, Comm=%s", event.Pid, unix.ByteSliceToString(event.Comm[:]))
	}
}

func printMapStats(ctx context.Context, objs *bpfObjects) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("\n📊 Hash Map Stats (PID → Count):")

			var (
				key   uint32
				value uint64
			)
			iter := objs.PidCounts.Iterate()
			count := 0
			for iter.Next(&key, &value) {
				if count < 5 { // Show first 5 entries
					log.Printf("  PID %d: %d executions", key, value)
				}
				count++
			}
			if err := iter.Err(); err != nil {
				log.Printf("iterating map: %v", err)
			}
			if count > 5 {
				log.Printf("  ... and %d more", count-5)
			}
			log.Println()
		}
	}
}
