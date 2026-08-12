package tui

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	networkobs "golan/internal/network"
)

func BenchmarkDenseNetworkOverviewRender(b *testing.B) {
	m := NewModelWithSize(160, 48)
	m.loading = false
	m.workspace = workspaceNetwork
	m.activeCard = cardNone
	session := networkobs.Session{ID: "benchmark", Mode: "listen", StartedAt: time.Unix(1, 0)}
	for index := 0; index < 512; index++ {
		mac := fmt.Sprintf("02:00:00:%02x:%02x:%02x", byte(index>>16), byte(index>>8), byte(index))
		session.Devices = append(session.Devices, networkobs.Device{
			Key: "en0/" + mac, MAC: mac, Adapter: "en0", Role: "host",
			IPs:       []string{"192.0.2." + strconv.Itoa(index%254+1)},
			FirstSeen: time.Unix(int64(index+1), 0), LastSeen: time.Unix(int64(index+1), 0),
			Protocols: []string{"DNS", "HTTP"},
		})
	}
	m.networkTracker = networkobs.LoadTracker(session)
	m.ensureNetworkSelection()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if view := m.View(); view == "" {
			b.Fatal("empty Workbench view")
		}
	}
}
