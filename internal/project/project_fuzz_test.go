package project

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzProjectManifestDecode(f *testing.F) {
	f.Add([]byte(`{"version":1,"id":"id","name":"lab"}`))
	f.Add([]byte(`{"version":1,"id":"id","name":"lab","captures":[{"id":"x","name":"x.pcap","path":"captures/../../escape","mode":"copy","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxManifestSize {
			t.Skip()
		}
		manifest, err := decodeManifest(data)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		roundTripped, err := decodeManifest(canonical)
		if err != nil {
			t.Fatalf("canonical manifest no longer decodes: %v", err)
		}
		canonicalAgain, err := json.Marshal(roundTripped)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canonical, canonicalAgain) {
			t.Fatalf("manifest canonicalization is not idempotent\nfirst:  %s\nsecond: %s", canonical, canonicalAgain)
		}
	})
}
