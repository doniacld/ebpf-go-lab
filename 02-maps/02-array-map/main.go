//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type config bpf config.c -- -I../../headers

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	log.Println("✅ eBPF program loaded")

	// STEP 1: Write configuration to array map
	cfg := bpfConfig{
		Enabled: 1,
		MinPid:  0, // Track ALL PIDs (including system processes)
	}
	key := uint32(0)
	if err := objs.ConfigMap.Update(&key, &cfg, 0); err != nil {
		log.Fatalf("updating config: %v", err)
	}
	log.Printf("✅ Configuration set: enabled=%d, min_pid=%d", cfg.Enabled, cfg.MinPid)

	// Attach kprobe
	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %v", err)
	}
	defer kp.Close()
	log.Println("✅ Kprobe attached to sys_execve")
	log.Println("📊 Counting executions (run commands to generate activity)...")

	// STEP 2: Read counter periodically
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for i := 0; i < 6; i++ {
		<-ticker.C

		// EXERCISE: Add code here to read the exec_count from the map
		// Hint: Use objs.ExecCount.Lookup(&key, &count)

		log.Printf("📊 Total executions (PID >= %d): [implement Lookup]", cfg.MinPid)
	}

	log.Println("\n✅ Done!")
}
