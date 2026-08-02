package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

// ErrDecisionNotLive reports an attempted frame mutation for a shadowed or
// unsupported rule. Callers must journal this rather than silently ignoring it.
var ErrDecisionNotLive = errors.New("policy decision is not live")

// ApplyTransformations applies safe frame-local edits and repairs IPv4 and
// transport checksums. Every edit must preserve the captured frame length.
func ApplyTransformations(frame traffic.Frame, decision Decision) (traffic.Frame, error) {
	if len(decision.Transformations) == 0 {
		return frame, nil
	}
	if decision.Status != dataplane.StatusLive {
		return frame, fmt.Errorf("%w: %s", ErrDecisionNotLive, decision.Status)
	}
	raw := frame.RawBytes()
	for _, transform := range decision.Transformations {
		var err error
		switch transform.Kind {
		case TransformField:
			err = rewriteField(raw, frame, transform.Field, transform.Replace)
		case TransformLiteral:
			err = replaceLiteral(raw, frame, []byte(transform.Search), []byte(transform.Replace), transform.Occurrence)
		case TransformRE2:
			err = replaceRE2(raw, frame, transform.Search, transform.Replace, transform.Occurrence)
		case TransformMasked:
			err = replaceMasked(raw, frame, transform.Search, transform.Replace, transform.Occurrence)
		default:
			err = fmt.Errorf("unknown transformation %q", transform.Kind)
		}
		if err != nil {
			return frame, err
		}
	}
	if err := repairChecksums(raw, frame); err != nil {
		return frame, err
	}
	return frame.WithRaw(raw), nil
}

func rewriteField(raw []byte, frame traffic.Frame, field traffic.Field, replacement string) error {
	ranges := frame.Ranges(field)
	if len(ranges) == 0 {
		return fmt.Errorf("field %s is absent", field)
	}
	r := ranges[0]
	if r.Start < 0 || r.End > len(raw) || r.Start >= r.End {
		return fmt.Errorf("field %s has an invalid byte range", field)
	}
	switch field {
	case traffic.FieldSrcMAC, traffic.FieldDstMAC:
		mac, err := net.ParseMAC(strings.TrimSpace(replacement))
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("replacement MAC %q is invalid", replacement)
		}
		copy(raw[r.Start:r.End], mac)
	case traffic.FieldSrcIP, traffic.FieldDstIP:
		address, err := netip.ParseAddr(strings.TrimSpace(replacement))
		if err != nil {
			return fmt.Errorf("replacement IP %q is invalid", replacement)
		}
		value := address.AsSlice()
		if len(value) != r.End-r.Start {
			return fmt.Errorf("replacement IP version differs from captured field")
		}
		copy(raw[r.Start:r.End], value)
	case traffic.FieldSrcPort, traffic.FieldDstPort, traffic.FieldEtherType:
		value, err := parseUint(replacement, 16)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(raw[r.Start:r.End], uint16(value))
	case traffic.FieldTTL:
		value, err := parseUint(replacement, 8)
		if err != nil {
			return err
		}
		raw[r.Start] = byte(value)
	case traffic.FieldDSCP:
		value, err := parseUint(replacement, 6)
		if err != nil || value > 63 {
			return fmt.Errorf("replacement DSCP %q is outside 0-63", replacement)
		}
		decoded := frame.Decoded()
		if decoded.IPVersion == 4 {
			raw[r.Start] = byte(value<<2) | raw[r.Start]&0x03
		} else if decoded.IPVersion == 6 && r.End-r.Start == 2 {
			raw[r.Start] = raw[r.Start]&0xf0 | byte(value>>2)
			raw[r.Start+1] = byte(value&0x03)<<6 | raw[r.Start+1]&0x3f
		} else {
			return fmt.Errorf("DSCP field has unsupported encoding")
		}
	case traffic.FieldVLAN:
		value, err := parseUint(replacement, 12)
		if err != nil || value > 4095 {
			return fmt.Errorf("replacement VLAN %q is outside 0-4095", replacement)
		}
		tci := binary.BigEndian.Uint16(raw[r.Start : r.Start+2])
		binary.BigEndian.PutUint16(raw[r.Start:r.Start+2], tci&0xf000|uint16(value))
	default:
		return fmt.Errorf("field %s is not safely rewritable", field)
	}
	return nil
}

func replaceLiteral(raw []byte, frame traffic.Frame, search, replacement []byte, occurrence Occurrence) error {
	if len(search) == 0 {
		return fmt.Errorf("literal search is empty")
	}
	if len(search) != len(replacement) {
		return fmt.Errorf("frame-local TCP replacement must preserve byte length")
	}
	payload, start, err := mutablePayload(raw, frame)
	if err != nil {
		return err
	}
	if occurrence != OccurrenceAll {
		index := bytes.Index(payload, search)
		if index < 0 {
			return fmt.Errorf("literal replacement did not match")
		}
		copy(raw[start+index:start+index+len(search)], replacement)
		return nil
	}
	if !bytes.Contains(payload, search) {
		return fmt.Errorf("literal replacement did not match")
	}
	copy(payload, bytes.ReplaceAll(payload, search, replacement))
	return nil
}

func replaceRE2(raw []byte, frame traffic.Frame, expression, replacement string, occurrence Occurrence) error {
	compiled, err := regexp.Compile(expression)
	if err != nil {
		return fmt.Errorf("compile replacement RE2: %w", err)
	}
	payload, _, err := mutablePayload(raw, frame)
	if err != nil {
		return err
	}
	var replaced []byte
	if occurrence == OccurrenceAll {
		replaced = compiled.ReplaceAll(payload, []byte(replacement))
	} else {
		location := compiled.FindSubmatchIndex(payload)
		if location == nil {
			return fmt.Errorf("RE2 replacement did not match")
		}
		replaced = append(replaced, payload[:location[0]]...)
		replaced = compiled.Expand(replaced, []byte(replacement), payload, location)
		replaced = append(replaced, payload[location[1]:]...)
	}
	if len(replaced) != len(payload) {
		return fmt.Errorf("frame-local TCP replacement must preserve byte length")
	}
	if bytes.Equal(replaced, payload) && !compiled.Match(payload) {
		return fmt.Errorf("RE2 replacement did not match")
	}
	copy(payload, replaced)
	return nil
}

func replaceMasked(raw []byte, frame traffic.Frame, search, replacement string, occurrence Occurrence) error {
	value, mask, err := parseMasked(search)
	if err != nil {
		return err
	}
	replacementBytes, err := decodeHexBytes(replacement)
	if err != nil {
		return err
	}
	if len(value) != len(replacementBytes) {
		return fmt.Errorf("frame-local masked replacement must preserve byte length")
	}
	payload, _, err := mutablePayload(raw, frame)
	if err != nil {
		return err
	}
	matched := false
	for offset := 0; offset+len(value) <= len(payload); {
		index := maskedIndex(payload[offset:], value, mask)
		if index < 0 {
			break
		}
		index += offset
		copy(payload[index:index+len(value)], replacementBytes)
		matched = true
		if occurrence != OccurrenceAll {
			break
		}
		offset = index + len(value)
	}
	if !matched {
		return fmt.Errorf("masked replacement did not match")
	}
	return nil
}

func mutablePayload(raw []byte, frame traffic.Frame) ([]byte, int, error) {
	ranges := frame.Ranges(traffic.FieldPayload)
	if len(ranges) != 1 {
		return nil, 0, fmt.Errorf("transport payload is absent")
	}
	r := ranges[0]
	if r.Start < 0 || r.End > len(raw) || r.Start > r.End {
		return nil, 0, fmt.Errorf("transport payload range is invalid")
	}
	return raw[r.Start:r.End], r.Start, nil
}

func repairChecksums(raw []byte, frame traffic.Frame) error {
	decoded := frame.Decoded()
	if decoded.IPVersion == 4 {
		ranges := frame.Ranges(traffic.FieldIPChecksum)
		if len(ranges) != 1 || ranges[0].Start < 10 || ranges[0].End > len(raw) {
			return fmt.Errorf("IPv4 checksum range is invalid")
		}
		checksumOffset := ranges[0].Start
		ipOffset := checksumOffset - 10
		headerLength := int(raw[ipOffset]&0x0f) * 4
		if headerLength < 20 || ipOffset+headerLength > len(raw) {
			return fmt.Errorf("IPv4 header is invalid")
		}
		raw[checksumOffset] = 0
		raw[checksumOffset+1] = 0
		binary.BigEndian.PutUint16(raw[checksumOffset:checksumOffset+2], internetChecksum(raw[ipOffset:ipOffset+headerLength]))
	}
	if decoded.IPProtocol != 6 && decoded.IPProtocol != 17 {
		return nil
	}
	field := traffic.FieldTCPChecksum
	if decoded.IPProtocol == 17 {
		field = traffic.FieldUDPChecksum
	}
	checksumRanges := frame.Ranges(field)
	portRanges := frame.Ranges(traffic.FieldSrcPort)
	if len(checksumRanges) != 1 || len(portRanges) != 1 {
		return fmt.Errorf("transport checksum fields are absent")
	}
	transportOffset := portRanges[0].Start
	transportEnd, pseudo, err := transportPseudoHeader(raw, frame, transportOffset)
	if err != nil {
		return err
	}
	checksumOffset := checksumRanges[0].Start
	if checksumOffset+2 > transportEnd {
		return fmt.Errorf("transport checksum range is invalid")
	}
	raw[checksumOffset] = 0
	raw[checksumOffset+1] = 0
	segment := raw[transportOffset:transportEnd]
	checksum := checksumParts(pseudo, segment)
	if decoded.IPProtocol == 17 && checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(raw[checksumOffset:checksumOffset+2], checksum)
	return nil
}

func transportPseudoHeader(raw []byte, frame traffic.Frame, transportOffset int) (int, []byte, error) {
	decoded := frame.Decoded()
	srcRanges := frame.Ranges(traffic.FieldSrcIP)
	dstRanges := frame.Ranges(traffic.FieldDstIP)
	if len(srcRanges) != 1 || len(dstRanges) != 1 {
		return 0, nil, fmt.Errorf("IP address ranges are absent")
	}
	if decoded.IPVersion == 4 {
		ipOffset := srcRanges[0].Start - 12
		if ipOffset < 0 || ipOffset+20 > len(raw) {
			return 0, nil, fmt.Errorf("IPv4 range is invalid")
		}
		totalLength := int(binary.BigEndian.Uint16(raw[ipOffset+2 : ipOffset+4]))
		end := ipOffset + totalLength
		if end < transportOffset || end > len(raw) {
			return 0, nil, fmt.Errorf("IPv4 transport length is invalid")
		}
		length := end - transportOffset
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], raw[srcRanges[0].Start:srcRanges[0].End])
		copy(pseudo[4:8], raw[dstRanges[0].Start:dstRanges[0].End])
		pseudo[9] = decoded.IPProtocol
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(length))
		return end, pseudo, nil
	}
	if decoded.IPVersion == 6 {
		ipOffset := srcRanges[0].Start - 8
		if ipOffset < 0 || ipOffset+40 > len(raw) {
			return 0, nil, fmt.Errorf("IPv6 range is invalid")
		}
		end := ipOffset + 40 + int(binary.BigEndian.Uint16(raw[ipOffset+4:ipOffset+6]))
		if end < transportOffset || end > len(raw) {
			return 0, nil, fmt.Errorf("IPv6 transport length is invalid")
		}
		length := end - transportOffset
		pseudo := make([]byte, 40)
		copy(pseudo[0:16], raw[srcRanges[0].Start:srcRanges[0].End])
		copy(pseudo[16:32], raw[dstRanges[0].Start:dstRanges[0].End])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(length))
		pseudo[39] = decoded.IPProtocol
		return end, pseudo, nil
	}
	return 0, nil, fmt.Errorf("unsupported IP version %d", decoded.IPVersion)
}

func internetChecksum(data []byte) uint16 {
	return checksumParts(data)
}

func checksumParts(parts ...[]byte) uint16 {
	var sum uint32
	var odd *byte
	for _, data := range parts {
		if odd != nil && len(data) > 0 {
			sum += uint32(*odd)<<8 | uint32(data[0])
			data = data[1:]
			odd = nil
		}
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			value := data[0]
			odd = &value
		}
	}
	if odd != nil {
		sum += uint32(*odd) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func parseUint(value string, bits int) (uint64, error) {
	value = strings.TrimSpace(value)
	base := 10
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		base = 0
	}
	parsed, err := strconv.ParseUint(value, base, bits)
	if err != nil {
		return 0, fmt.Errorf("replacement integer %q is invalid", value)
	}
	return parsed, nil
}

func decodeHexBytes(value string) ([]byte, error) {
	tokens := strings.Fields(strings.ReplaceAll(strings.TrimSpace(value), ":", " "))
	if len(tokens) == 0 {
		return nil, fmt.Errorf("replacement hex is empty")
	}
	out := make([]byte, len(tokens))
	for i, token := range tokens {
		parsed, err := strconv.ParseUint(token, 16, 8)
		if err != nil || len(token) != 2 {
			return nil, fmt.Errorf("replacement hex byte %q is invalid", token)
		}
		out[i] = byte(parsed)
	}
	return out, nil
}
