package hardwaretest

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigDisabledWithoutOptIn(t *testing.T) {
	cfg, err := loadConfig(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("hardware suite enabled without acknowledgement")
	}
}

func TestLoadConfigRequiresExactAcknowledgementAndExplicitCases(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "case without acknowledgement", env: map[string]string{envCases: string(casePFSyntax)}, want: envAcknowledgement},
		{name: "wrong acknowledgement", env: map[string]string{envAcknowledgement: "yes", envCases: string(casePFSyntax)}, want: envAcknowledgement},
		{name: "no cases", env: map[string]string{envAcknowledgement: acknowledgement}, want: envCases},
		{name: "unknown case", env: map[string]string{envAcknowledgement: acknowledgement, envCases: "fast,unknown"}, want: "unknown case"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadConfig(mapReader(test.env))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestLoadConfigCanonicalizesCasesAndDefaults(t *testing.T) {
	env := map[string]string{
		envAcknowledgement: acknowledgement,
		envCases:           " controlled,PF-SYNTAX,controlled ",
		envHost:            " en7 ",
		envSwitch:          "en8",
		envExpectEAPOL:     "true",
	}
	cfg, err := loadConfig(mapReader(env))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || !reflect.DeepEqual(cfg.Cases, []hardwareCase{casePFSyntax, caseControlled}) {
		t.Fatalf("config=%#v", cfg)
	}
	if cfg.Host != "en7" || cfg.Switch != "en8" || cfg.Duration != 15*time.Second || cfg.ActiveTimeout != 90*time.Second || cfg.MinPackets != 1 || !cfg.ExpectEAPOL {
		t.Fatalf("defaults=%#v", cfg)
	}
}

func TestLoadConfigValidatesCaseRequirementsAndBounds(t *testing.T) {
	base := map[string]string{envAcknowledgement: acknowledgement}
	tests := []struct {
		name string
		set  map[string]string
		want string
	}{
		{name: "inline adapters", set: map[string]string{envCases: string(caseControlled)}, want: envHost},
		{name: "same inline adapter", set: map[string]string{envCases: string(caseControlled), envHost: "en7", envSwitch: "en7"}, want: "must differ"},
		{name: "fast target", set: map[string]string{envCases: string(caseFast), envHost: "en7", envSwitch: "en8"}, want: envTargetMAC},
		{name: "edge downstream", set: map[string]string{envCases: string(caseEdgeRoute)}, want: envDownstream},
		{name: "port forward", set: map[string]string{envCases: string(caseEdgeForward), envDownstream: "en9"}, want: envPortForwardProto},
		{name: "duration", set: map[string]string{envCases: string(casePFSyntax), envDuration: "500ms"}, want: envDuration},
		{name: "packet count", set: map[string]string{envCases: string(casePFSyntax), envMinPackets: "0"}, want: envMinPackets},
		{name: "boolean", set: map[string]string{envCases: string(casePFSyntax), envExpectVLAN: "sometimes"}, want: envExpectVLAN},
		{name: "nat cidr", set: map[string]string{envCases: string(casePFSyntax), envNATIP: "192.0.2.4"}, want: envNATCIDR},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := make(map[string]string, len(base)+len(test.set))
			for key, value := range base {
				env[key] = value
			}
			for key, value := range test.set {
				env[key] = value
			}
			_, err := loadConfig(mapReader(env))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestLoadConfigAcceptsCompleteSelection(t *testing.T) {
	env := map[string]string{
		envAcknowledgement:   acknowledgement,
		envCases:             strings.Join(knownCaseNames(), ","),
		envHost:              "en7",
		envSwitch:            "en8",
		envTargetMAC:         "02:00:00:00:00:01",
		envDownstream:        "en9",
		envUpstream:          "en0",
		envDuration:          "30s",
		envActiveTimeout:     "2m",
		envMinPackets:        "25",
		envAllowDefaultRoute: "true",
		envNATIP:             "192.0.2.4",
		envNATCIDR:           "192.0.2.0/24",
		envPortForwardProto:  "tcp",
		envPortForwardListen: "18443",
		envPortForwardTarget: "8443",
	}
	cfg, err := loadConfig(mapReader(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Cases) != len(caseOrder) || cfg.Duration != 30*time.Second || cfg.ActiveTimeout != 2*time.Minute || cfg.MinPackets != 25 || !cfg.AllowDefaultRoute {
		t.Fatalf("config=%#v", cfg)
	}
}

func mapReader(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}
