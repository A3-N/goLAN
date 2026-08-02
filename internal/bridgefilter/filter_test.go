package bridgefilter

import "testing"

func TestValidBridgeInterfaceName(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "bridge0", want: true},
		{name: " bridge17 ", want: true},
		{name: "bridge12345678", want: true},
		{name: "", want: false},
		{name: "bridge", want: false},
		{name: "bridge-1", want: false},
		{name: "en0", want: false},
		{name: "bridge1234567890", want: false},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validBridgeInterfaceName(test.name); got != test.want {
				t.Fatalf("validBridgeInterfaceName(%q) = %t, want %t", test.name, got, test.want)
			}
		})
	}
}
