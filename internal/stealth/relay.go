package stealth

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ControlRelay forwards L2 control frames that compliant bridges may consume
// or suppress instead of forwarding, notably 802.1X EAPOL and LLDP.
type ControlRelay struct {
	ifaceA string
	ifaceB string

	mu     sync.Mutex
	recent map[string]map[uint64]time.Time
}

func NewControlRelay(ifaceA, ifaceB string) *ControlRelay {
	return &ControlRelay{
		ifaceA: ifaceA,
		ifaceB: ifaceB,
		recent: map[string]map[uint64]time.Time{
			ifaceA: {},
			ifaceB: {},
		},
	}
}

func (r *ControlRelay) Run(ctx context.Context, eventLog func(string)) {
	if eventLog == nil {
		eventLog = func(string) {}
	}

	handleA, err := openControlHandle(r.ifaceA, eventLog)
	if err != nil {
		eventLog(fmt.Sprintf("[!] L2 control relay unavailable on %s: %v", r.ifaceA, err))
		return
	}
	defer handleA.Close()

	handleB, err := openControlHandle(r.ifaceB, eventLog)
	if err != nil {
		eventLog(fmt.Sprintf("[!] L2 control relay unavailable on %s: %v", r.ifaceB, err))
		return
	}
	defer handleB.Close()

	eventLog("[+] L2 control relay active for EAPOL, LLDP, and CDP frames.")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.relay(ctx, "Device -> Switch", r.ifaceB, handleA, handleB, eventLog)
	}()
	go func() {
		defer wg.Done()
		r.relay(ctx, "Switch -> Device", r.ifaceA, handleB, handleA, eventLog)
	}()

	<-ctx.Done()
	wg.Wait()
	eventLog("[*] L2 control relay stopped.")
}

func openControlHandle(iface string, eventLog func(string)) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 262144, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		eventLog(fmt.Sprintf("[!] pcap inbound direction unavailable on %s: %v", iface, err))
	}

	filter := controlFrameFilter()
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("setting BPF filter: %w", err)
	}

	return handle, nil
}

func (r *ControlRelay) relay(ctx context.Context, direction, dstIface string, src, dst *pcap.Handle, eventLog func(string)) {
	source := gopacket.NewPacketSource(src, src.LinkType())
	packets := source.Packets()
	count := 0

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if packet == nil || len(packet.Data()) == 0 {
				continue
			}

			data := packet.Data()
			if !isControlFrame(data) {
				continue
			}
			if r.wasInjected(dstIface, data) {
				continue
			}

			r.remember(dstIface, data)
			if err := dst.WritePacketData(data); err != nil {
				eventLog(fmt.Sprintf("[!] L2 control relay write failed (%s): %v", direction, err))
				continue
			}

			count++
			if count <= 10 || count%50 == 0 {
				eventLog(fmt.Sprintf("> Relayed L2 control frame %s (%d bytes, count %d)", direction, len(data), count))
			}
		}
	}
}

func (r *ControlRelay) remember(iface string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entries := r.recent[iface]
	now := time.Now()
	entries[frameHash(data)] = now
	for hash, seen := range entries {
		if now.Sub(seen) > 2*time.Second {
			delete(entries, hash)
		}
	}
}

func (r *ControlRelay) wasInjected(iface string, data []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	entries := r.recent[iface]
	hash := frameHash(data)
	if _, ok := entries[hash]; ok {
		delete(entries, hash)
		return true
	}
	return false
}

func frameHash(data []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(data)
	return h.Sum64()
}

func controlFrameFilter() string {
	base := "ether proto 0x888e or ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc or ether dst 01:80:c2:00:00:03 or ether dst 01:80:c2:00:00:0e"
	return base + " or (vlan and (" + base + ")) or (vlan and vlan and (" + base + "))"
}

func isControlFrame(data []byte) bool {
	if len(data) < 14 {
		return false
	}

	if macEqualBytes(data[0:6], []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}) {
		return true
	}

	offset := 12
	etherType := uint16(data[offset])<<8 | uint16(data[offset+1])
	for tags := 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88a8); tags++ {
		offset += 4
		if len(data) < offset+2 {
			return false
		}
		etherType = uint16(data[offset])<<8 | uint16(data[offset+1])
	}

	return etherType == 0x888e || etherType == 0x88cc
}

func macEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
