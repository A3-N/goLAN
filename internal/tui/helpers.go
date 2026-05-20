package tui

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

func hostKey(mac, ip string) string {
	mac = strings.TrimSpace(strings.ToLower(mac))
	ip = strings.TrimSpace(ip)
	if mac != "" && mac != "unknown" {
		return "mac:" + mac
	}
	if ip != "" && ip != "unknown" {
		return "ip:" + ip
	}
	return ""
}

func edgeKey(src, dst, proto string, srcPort, dstPort, vlan uint16) string {
	return strings.Join([]string{src, dst, proto, portKey(srcPort), portKey(dstPort), portKey(vlan)}, "|")
}

func portKey(v uint16) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%d", v)
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if len(ip) > 0 {
			out = appendUniqueString(out, ip.String())
		}
	}
	sort.Strings(out)
	return out
}

func nonUnknownStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" && v != "unknown" {
			out = appendUniqueString(out, v)
		}
	}
	return out
}

func appendUniqueStrings(values []string, more ...string) []string {
	for _, value := range more {
		values = appendUniqueString(values, value)
	}
	sort.Strings(values)
	return values
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || value == "unknown" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func firstNonUnknown(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" && value != "unknown" {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func preferKind(existing, candidate string) string {
	if existing == "" {
		return candidate
	}
	rank := map[string]int{
		"target":   10,
		"switch":   9,
		"gateway":  9,
		"dhcp":     8,
		"radius":   8,
		"nas":      7,
		"dns":      6,
		"printer":  6,
		"network":  6,
		"windows":  5,
		"unix":     5,
		"apple":    5,
		"phone":    5,
		"web":      4,
		"ntp":      4,
		"service":  3,
		"external": 2,
		"host":     1,
	}
	if rank[candidate] > rank[existing] {
		return candidate
	}
	return firstNonEmpty(existing, candidate)
}

func firstTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func minTime(values ...time.Time) time.Time {
	var out time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if out.IsZero() || value.Before(out) {
			out = value
		}
	}
	return out
}

func maxTime(values ...time.Time) time.Time {
	var out time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if out.IsZero() || value.After(out) {
			out = value
		}
	}
	return out
}

func maxUint64(a, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}
