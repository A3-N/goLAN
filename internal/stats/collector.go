package stats

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// InterfaceStats holds traffic counters for a single interface.
type InterfaceStats struct {
	Name       string
	RxBytes    uint64
	TxBytes    uint64
	RxPackets  uint64
	TxPackets  uint64
	RxErrors   uint64
	TxErrors   uint64
	RxDropped  uint64
	TxDropped  uint64
	MediaActive bool
}

// InterfaceDelta holds computed deltas and throughput for a single interface.
type InterfaceDelta struct {
	Stats        InterfaceStats
	RxBytesPerSec float64
	TxBytesPerSec float64
	RxPktPerSec   float64
	TxPktPerSec   float64
}

// StatsUpdate is sent to the TUI on each poll interval.
type StatsUpdate struct {
	IfaceA    InterfaceDelta
	IfaceB    InterfaceDelta
	Bridge    InterfaceStats // stats for the bridge interface itself
	Uptime    time.Duration
	Timestamp time.Time
}

// Collector polls interface statistics at a configured interval.
type Collector struct {
	ifaceA   string
	ifaceB   string
	bridgeIf string // e.g. "bridge0"
	interval time.Duration

	mu       sync.Mutex
	history  map[string][]float64 // rolling throughput history per interface
	maxHist  int
	prevA    *InterfaceStats
	prevB    *InterfaceStats
	prevTime time.Time
	started  time.Time
	running  bool // guards against double-start
}

// NewCollector creates a new stats collector for two bridged interfaces.
func NewCollector(ifaceA, ifaceB, bridgeIf string, interval time.Duration) *Collector {
	return &Collector{
		ifaceA:   ifaceA,
		ifaceB:   ifaceB,
		bridgeIf: bridgeIf,
		interval: interval,
		history: map[string][]float64{
			ifaceA + "_rx": {},
			ifaceA + "_tx": {},
			ifaceB + "_rx": {},
			ifaceB + "_tx": {},
		},
		maxHist: 60, // 60 samples = 30 seconds at 500ms interval
	}
}

// Start begins polling and returns a channel of StatsUpdate messages.
// The channel is closed when the context is cancelled.
// Safe to call only once per collector; subsequent calls return a nil channel.
func (c *Collector) Start(ctx context.Context) <-chan StatsUpdate {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil // Already running — prevent goroutine/channel leak
	}
	c.running = true
	c.mu.Unlock()

	ch := make(chan StatsUpdate, 1)
	c.started = time.Now()

	go func() {
		defer func() {
			close(ch)
			c.mu.Lock()
			c.running = false
			c.mu.Unlock()
		}()
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				update := c.poll()
				select {
				case ch <- update:
				default:
					// Drop if TUI isn't consuming fast enough.
				}
			}
		}
	}()

	return ch
}

// History returns the rolling throughput history for sparklines.
func (c *Collector) History(key string) []float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.history[key]
	out := make([]float64, len(h))
	copy(out, h)
	return out
}

// poll reads current stats, computes deltas, and updates history.
func (c *Collector) poll() StatsUpdate {
	now := time.Now()

	statsA := readInterfaceStats(c.ifaceA)
	statsB := readInterfaceStats(c.ifaceB)
	statsBr := readInterfaceStats(c.bridgeIf)

	c.mu.Lock()
	defer c.mu.Unlock()

	var deltaA, deltaB InterfaceDelta
	deltaA.Stats = statsA
	deltaB.Stats = statsB

	if c.prevA != nil && c.prevB != nil {
		elapsed := now.Sub(c.prevTime).Seconds()
		if elapsed > 0 {
			// Use safeDelta to prevent uint64 underflow on counter resets/rollovers.
			deltaA.RxBytesPerSec = float64(safeDelta(statsA.RxBytes, c.prevA.RxBytes)) / elapsed
			deltaA.TxBytesPerSec = float64(safeDelta(statsA.TxBytes, c.prevA.TxBytes)) / elapsed
			deltaA.RxPktPerSec = float64(safeDelta(statsA.RxPackets, c.prevA.RxPackets)) / elapsed
			deltaA.TxPktPerSec = float64(safeDelta(statsA.TxPackets, c.prevA.TxPackets)) / elapsed

			deltaB.RxBytesPerSec = float64(safeDelta(statsB.RxBytes, c.prevB.RxBytes)) / elapsed
			deltaB.TxBytesPerSec = float64(safeDelta(statsB.TxBytes, c.prevB.TxBytes)) / elapsed
			deltaB.RxPktPerSec = float64(safeDelta(statsB.RxPackets, c.prevB.RxPackets)) / elapsed
			deltaB.TxPktPerSec = float64(safeDelta(statsB.TxPackets, c.prevB.TxPackets)) / elapsed

			// Append to history.
			c.appendHistory(c.ifaceA+"_rx", deltaA.RxBytesPerSec)
			c.appendHistory(c.ifaceA+"_tx", deltaA.TxBytesPerSec)
			c.appendHistory(c.ifaceB+"_rx", deltaB.RxBytesPerSec)
			c.appendHistory(c.ifaceB+"_tx", deltaB.TxBytesPerSec)
		}
	}

	c.prevA = &statsA
	c.prevB = &statsB
	c.prevTime = now

	return StatsUpdate{
		IfaceA:    deltaA,
		IfaceB:    deltaB,
		Bridge:    statsBr,
		Uptime:    time.Since(c.started),
		Timestamp: now,
	}
}

// appendHistory adds a value to the rolling history, trimming to maxHist.
func (c *Collector) appendHistory(key string, val float64) {
	h := c.history[key]
	h = append(h, val)
	if len(h) > c.maxHist {
		h = h[len(h)-c.maxHist:]
	}
	c.history[key] = h
}

// readInterfaceStats parses `netstat -I <iface> -b` for byte counters.
//
// macOS netstat -bI output has columns like:
// Name  Mtu   Network       Address            Ibytes   Ipkts  Ierrs  Obytes   Opkts  Oerrs  Coll   Drop
// en0   1500  <Link#4>      aa:bb:cc:dd:ee:ff  1234567  8901   0      2345678  9012   0      0      0
func readInterfaceStats(ifaceName string) InterfaceStats {
	stats := InterfaceStats{Name: ifaceName}

	out, err := exec.Command("netstat", "-I", ifaceName, "-b").Output()
	if err != nil {
		return stats
	}

	// Capture physical media link state natively
	if outMedia, err := exec.Command("ifconfig", ifaceName).Output(); err == nil {
		stats.MediaActive = strings.Contains(string(outMedia), "status: active")
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return stats
	}

	// Find the header line to get column indices.
	headerIdx := -1
	for i, line := range lines {
		if strings.Contains(line, "Ibytes") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 || headerIdx+1 >= len(lines) {
		return stats
	}

	// Parse column positions from header.
	header := lines[headerIdx]
	cols := strings.Fields(header)
	colIndex := make(map[string]int)
	for i, col := range cols {
		colIndex[col] = i
	}

	// Parse the first data line that matches our interface (Link line with bytes).
	for _, line := range lines[headerIdx+1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Skip lines for IP networks (we want the <Link#N> line with byte counts).
		if fields[0] != ifaceName {
			continue
		}
		// The link line has the raw byte counters.
		if idx, ok := colIndex["Ibytes"]; ok && idx < len(fields) {
			stats.RxBytes = parseUint(fields[idx])
		}
		if idx, ok := colIndex["Obytes"]; ok && idx < len(fields) {
			stats.TxBytes = parseUint(fields[idx])
		}
		if idx, ok := colIndex["Ipkts"]; ok && idx < len(fields) {
			stats.RxPackets = parseUint(fields[idx])
		}
		if idx, ok := colIndex["Opkts"]; ok && idx < len(fields) {
			stats.TxPackets = parseUint(fields[idx])
		}
		if idx, ok := colIndex["Ierrs"]; ok && idx < len(fields) {
			stats.RxErrors = parseUint(fields[idx])
		}
		if idx, ok := colIndex["Oerrs"]; ok && idx < len(fields) {
			stats.TxErrors = parseUint(fields[idx])
		}
		if idx, ok := colIndex["Drop"]; ok && idx < len(fields) {
			stats.RxDropped = parseUint(fields[idx])
		}
		// Found the link line, we're done.
		break
	}

	return stats
}

// HumanizeBytes formats bytes into a human-readable string.
func HumanizeBytes(b uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// HumanizeThroughput formats bytes/sec into a human-readable throughput string.
func HumanizeThroughput(bps float64) string {
	const (
		Kbps = 1000.0
		Mbps = 1000.0 * Kbps
		Gbps = 1000.0 * Mbps
	)

	bitsPerSec := bps * 8
	switch {
	case bitsPerSec >= Gbps:
		return fmt.Sprintf("%.2f Gbps", bitsPerSec/Gbps)
	case bitsPerSec >= Mbps:
		return fmt.Sprintf("%.1f Mbps", bitsPerSec/Mbps)
	case bitsPerSec >= Kbps:
		return fmt.Sprintf("%.0f Kbps", bitsPerSec/Kbps)
	default:
		return fmt.Sprintf("%.0f bps", bitsPerSec)
	}
}

// HumanizeDuration formats a duration into a concise string.
func HumanizeDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// safeDelta returns (current - prev) if current >= prev, or 0 if the counter
// has wrapped/reset. This prevents uint64 underflow from producing massive
// spurious throughput values.
func safeDelta(current, prev uint64) uint64 {
	if current >= prev {
		return current - prev
	}
	return 0
}
