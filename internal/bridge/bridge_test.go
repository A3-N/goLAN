package bridge

import "testing"

func TestManualIPv4RestoreArgs(t *testing.T) {
	got := manualIPv4RestoreArgs([]string{
		"192.168.10.42/24",
		"fe80::1/64",
		"not-an-address",
	})

	if len(got) != 1 {
		t.Fatalf("restore args length = %d", len(got))
	}
	want := []string{"192.168.10.42", "netmask", "255.255.255.0", "alias"}
	for i := range want {
		if got[0][i] != want[i] {
			t.Fatalf("arg[%d] = %q, want %q", i, got[0][i], want[i])
		}
	}
}
