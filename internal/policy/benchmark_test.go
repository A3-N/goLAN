package policy

import (
	"encoding/binary"
	"strconv"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

func BenchmarkCompileRepresentativePolicy(b *testing.B) {
	base, err := Preset("web-only")
	if err != nil {
		b.Fatal(err)
	}
	rules := make([]Rule, 0, 256)
	for index := 0; index < 256; index++ {
		rule := base[index%len(base)]
		rule.ID += "-" + strconv.Itoa(index)
		rule.Priority = 256 - index
		rules = append(rules, rule)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Compile("benchmark", rules); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvaluateRepresentativePolicy(b *testing.B) {
	rules, err := Preset("web-only")
	if err != nil {
		b.Fatal(err)
	}
	compiled, err := Compile("benchmark", rules)
	if err != nil {
		b.Fatal(err)
	}
	frame := testTCPFrameForBenchmark(b, 443)
	flow := traffic.NewTracker(1).Observe(frame)
	capabilities := dataplane.ForMode(dataplane.ModeControlledBridge)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		decision := compiled.Evaluate(frame, flow, capabilities)
		if decision.WinningRuleID != "web-only-web" {
			b.Fatalf("winning rule=%s", decision.WinningRuleID)
		}
	}
}

func testTCPFrameForBenchmark(b *testing.B, destinationPort uint16) traffic.Frame {
	b.Helper()
	payload := []byte("GET / HTTP/1.1\r\nHost: benchmark.test\r\n\r\n")
	data := make([]byte, 14+20+20+len(payload))
	copy(data[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(data[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(data[12:14], 0x0800)
	ip := data[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:4], uint16(40+len(payload)))
	copy(ip[12:16], []byte{192, 0, 2, 10})
	copy(ip[16:20], []byte{198, 51, 100, 20})
	tcp := data[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], 49152)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12] = 5 << 4
	copy(data[54:], payload)
	return traffic.Normalize(data, traffic.CaptureMetadata{}, "benchmark", traffic.SideHost, traffic.DirectionOutbound)
}
