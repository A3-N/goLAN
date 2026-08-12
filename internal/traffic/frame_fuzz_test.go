package traffic

import (
	"testing"
	"time"
)

func FuzzNormalize(f *testing.F) {
	f.Add([]byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x88, 0xb5})
	f.Add([]byte{0x45})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		owned := append([]byte(nil), data...)
		frame := Normalize(owned, CaptureMetadata{Timestamp: time.Unix(1, 2)}, "fuzz0", SideHost, DirectionOutbound)
		before := frame.RawBytes()
		if len(owned) > 0 {
			owned[0] ^= 0xff
		}
		after := frame.RawBytes()
		if string(before) != string(after) {
			t.Fatal("normalized frame retained caller-owned memory")
		}
		_ = frame.Decoded()
		_ = frame.Offsets()
		_ = frame.Sensitivity()
	})
}
