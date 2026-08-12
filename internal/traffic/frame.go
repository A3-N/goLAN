package traffic

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketID is a deterministic identifier for one normalized evidence item.
type PacketID string

// TopologySide identifies where a frame entered the normalized pipeline.
type TopologySide string

// Topology sides are deliberately independent of operating-system interface
// names so saved policies remain portable across machines.
const (
	SideUnknown    TopologySide = "unknown"
	SideHost       TopologySide = "host"
	SideSwitch     TopologySide = "switch"
	SideLocal      TopologySide = "local"
	SideUpstream   TopologySide = "upstream"
	SideDownstream TopologySide = "downstream"
)

// Direction describes the semantic direction of a captured frame.
type Direction string

// Direction values cover inline Layer 2 and routed endpoint topologies.
const (
	DirectionUnknown      Direction = "unknown"
	DirectionHostToSwitch Direction = "host-to-switch"
	DirectionSwitchToHost Direction = "switch-to-host"
	DirectionInbound      Direction = "inbound"
	DirectionOutbound     Direction = "outbound"
)

// EvidenceKind identifies the physical packet evidence boundary.
type EvidenceKind string

const EvidencePacket EvidenceKind = "packet"

// CaptureMetadata records capture facts without retaining a capture handle.
type CaptureMetadata struct {
	Timestamp      time.Time `json:"timestamp"`
	CaptureLength  int       `json:"capture_length"`
	OriginalLength int       `json:"original_length"`
	InterfaceIndex int       `json:"interface_index,omitempty"`
	LinkType       int       `json:"link_type"`
	Source         string    `json:"source,omitempty"`
}

// VLAN records one tag in outer-to-inner order.
type VLAN struct {
	EtherType uint16 `json:"ether_type"`
	ID        uint16 `json:"id"`
	Priority  uint8  `json:"priority"`
	Drop      bool   `json:"drop_eligible"`
}

// TCPFlags stores the wire flag byte and NS bit in a compact comparable form.
type TCPFlags uint16

// DNSRecord is a bounded, payload-free DNS answer used for readable service
// discovery. TXT values and arbitrary resource data are deliberately omitted.
type DNSRecord struct {
	Name   string `json:"name"`
	Type   uint16 `json:"type"`
	Target string `json:"target,omitempty"`
	Port   uint16 `json:"port,omitempty"`
}

// DecodedFields contains normalized values used by rules and renderers. Slices
// and maps are copied whenever a Frame crosses an ownership boundary.
type DecodedFields struct {
	SrcMAC      string              `json:"src_mac,omitempty"`
	DstMAC      string              `json:"dst_mac,omitempty"`
	EtherType   uint16              `json:"ether_type,omitempty"`
	VLANs       []VLAN              `json:"vlans,omitempty"`
	IPVersion   uint8               `json:"ip_version,omitempty"`
	SrcIP       string              `json:"src_ip,omitempty"`
	DstIP       string              `json:"dst_ip,omitempty"`
	IPProtocol  uint8               `json:"ip_protocol,omitempty"`
	DSCP        uint8               `json:"dscp,omitempty"`
	TTL         uint8               `json:"ttl,omitempty"`
	SrcPort     uint16              `json:"src_port,omitempty"`
	DstPort     uint16              `json:"dst_port,omitempty"`
	TCPFlags    TCPFlags            `json:"tcp_flags,omitempty"`
	ICMPType    uint8               `json:"icmp_type,omitempty"`
	ICMPCode    uint8               `json:"icmp_code,omitempty"`
	EAPOLType   uint8               `json:"eapol_type,omitempty"`
	DNSNames    []string            `json:"dns_names,omitempty"`
	DNSRecords  []DNSRecord         `json:"dns_records,omitempty"`
	DNSType     uint16              `json:"dns_type,omitempty"`
	DNSResponse bool                `json:"dns_response,omitempty"`
	HTTPMethod  string              `json:"http_method,omitempty"`
	HTTPStatus  uint16              `json:"http_status,omitempty"`
	HTTPHost    string              `json:"http_host,omitempty"`
	HTTPPath    string              `json:"http_path,omitempty"`
	HTTPHeader  map[string][]string `json:"http_headers,omitempty"`
	Malformed   bool                `json:"malformed,omitempty"`
}

// Field identifies a wire field with one or more byte ranges.
type Field string

// Wire field names are stable policy and inspector vocabulary.
const (
	FieldDstMAC      Field = "ethernet.dst"
	FieldSrcMAC      Field = "ethernet.src"
	FieldEtherType   Field = "ethernet.type"
	FieldVLAN        Field = "vlan"
	FieldDSCP        Field = "ip.dscp"
	FieldTTL         Field = "ip.ttl"
	FieldSrcIP       Field = "ip.src"
	FieldDstIP       Field = "ip.dst"
	FieldSrcPort     Field = "transport.src_port"
	FieldDstPort     Field = "transport.dst_port"
	FieldPayload     Field = "transport.payload"
	FieldIPChecksum  Field = "ipv4.checksum"
	FieldTCPChecksum Field = "tcp.checksum"
	FieldUDPChecksum Field = "udp.checksum"
)

// ByteRange is a half-open range in the original frame.
type ByteRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// SensitivityMarker labels a byte range that generic logs must not expose.
type SensitivityMarker struct {
	Range ByteRange `json:"range"`
	Kind  string    `json:"kind"`
}

// Frame is an immutable normalized packet. Raw bytes and
// collection fields are private; accessors return copies so capture,
// forwarding, and the TUI cannot mutate one another's evidence buffers.
type Frame struct {
	ID        PacketID        `json:"id"`
	Kind      EvidenceKind    `json:"kind"`
	Timestamp time.Time       `json:"timestamp"`
	Capture   CaptureMetadata `json:"capture"`
	Ingress   string          `json:"ingress,omitempty"`
	Side      TopologySide    `json:"side"`
	Direction Direction       `json:"direction"`

	raw         []byte
	decoded     DecodedFields
	offsets     map[Field][]ByteRange
	sensitivity []SensitivityMarker
}

// Normalize copies and decodes an Ethernet frame. Malformed protocol layers
// are represented by DecodedFields.Malformed and never cause a panic.
func Normalize(data []byte, metadata CaptureMetadata, ingress string, side TopologySide, direction Direction) Frame {
	raw := append([]byte(nil), data...)
	metadata.Timestamp = metadata.Timestamp.UTC()
	if metadata.CaptureLength == 0 {
		metadata.CaptureLength = len(raw)
	}
	if metadata.OriginalLength == 0 {
		metadata.OriginalLength = len(raw)
	}
	f := Frame{
		Kind:      EvidencePacket,
		Timestamp: metadata.Timestamp,
		Capture:   metadata,
		Ingress:   strings.TrimSpace(ingress),
		Side:      normalizeSide(side),
		Direction: normalizeDirection(direction),
		raw:       raw,
		offsets:   make(map[Field][]ByteRange),
	}
	f.ID = packetID(f)
	f.decode()
	return f
}

// RawBytes returns a copy of the captured frame bytes.
func (f Frame) RawBytes() []byte {
	return append([]byte(nil), f.raw...)
}

// RawLength returns the owned captured byte count without copying payload data.
func (f Frame) RawLength() int {
	return len(f.raw)
}

// Decoded returns a deep copy of normalized protocol fields.
func (f Frame) Decoded() DecodedFields {
	return cloneDecoded(f.decoded)
}

// Offsets returns a deep copy of decoded field byte ranges.
func (f Frame) Offsets() map[Field][]ByteRange {
	out := make(map[Field][]ByteRange, len(f.offsets))
	for field, ranges := range f.offsets {
		out[field] = append([]ByteRange(nil), ranges...)
	}
	return out
}

// Ranges returns a copy of the byte ranges for field.
func (f Frame) Ranges(field Field) []ByteRange {
	return append([]ByteRange(nil), f.offsets[field]...)
}

// Sensitivity returns a copy of semantic sensitivity markers.
func (f Frame) Sensitivity() []SensitivityMarker {
	return append([]SensitivityMarker(nil), f.sensitivity...)
}

// WithSensitivity returns a new frame with an additional validated marker.
func (f Frame) WithSensitivity(marker SensitivityMarker) Frame {
	if marker.Range.Start < 0 || marker.Range.End < marker.Range.Start || marker.Range.End > len(f.raw) {
		return f
	}
	out := f.clone()
	marker.Kind = strings.TrimSpace(marker.Kind)
	out.sensitivity = append(out.sensitivity, marker)
	return out
}

// WithRaw returns a newly normalized frame using replacement bytes while
// preserving capture provenance. The new packet receives its own stable ID.
func (f Frame) WithRaw(data []byte) Frame {
	metadata := f.Capture
	metadata.CaptureLength = len(data)
	metadata.OriginalLength = len(data)
	return Normalize(data, metadata, f.Ingress, f.Side, f.Direction)
}

func (f Frame) clone() Frame {
	f.raw = append([]byte(nil), f.raw...)
	f.decoded = cloneDecoded(f.decoded)
	f.offsets = f.Offsets()
	f.sensitivity = f.Sensitivity()
	return f
}

func (f *Frame) decode() {
	if len(f.raw) < 14 {
		f.decoded.Malformed = true
		return
	}
	f.decoded.DstMAC = formatMAC(f.raw[0:6])
	f.decoded.SrcMAC = formatMAC(f.raw[6:12])
	f.offsets[FieldDstMAC] = []ByteRange{{Start: 0, End: 6}}
	f.offsets[FieldSrcMAC] = []ByteRange{{Start: 6, End: 12}}
	f.offsets[FieldEtherType] = []ByteRange{{Start: 12, End: 14}}

	etherType := binary.BigEndian.Uint16(f.raw[12:14])
	offset := 14
	for isVLANEtherType(etherType) {
		if offset+4 > len(f.raw) {
			f.decoded.Malformed = true
			return
		}
		tci := binary.BigEndian.Uint16(f.raw[offset : offset+2])
		f.decoded.VLANs = append(f.decoded.VLANs, VLAN{
			EtherType: etherType,
			ID:        tci & 0x0fff,
			Priority:  uint8(tci >> 13),
			Drop:      tci&0x1000 != 0,
		})
		f.offsets[FieldVLAN] = append(f.offsets[FieldVLAN], ByteRange{Start: offset, End: offset + 4})
		etherType = binary.BigEndian.Uint16(f.raw[offset+2 : offset+4])
		offset += 4
	}
	f.decoded.EtherType = etherType
	switch etherType {
	case uint16(layers.EthernetTypeIPv4):
		f.decodeIPv4(offset)
	case uint16(layers.EthernetTypeIPv6):
		f.decodeIPv6(offset)
	case 0x888e:
		if offset+4 > len(f.raw) {
			f.decoded.Malformed = true
		} else {
			f.decoded.EAPOLType = f.raw[offset+1]
			f.offsets[FieldPayload] = []ByteRange{{Start: offset + 4, End: len(f.raw)}}
		}
	}
	f.decodeApplication()
}

func (f *Frame) decodeIPv4(offset int) {
	if offset+20 > len(f.raw) || f.raw[offset]>>4 != 4 {
		f.decoded.Malformed = true
		return
	}
	headerLength := int(f.raw[offset]&0x0f) * 4
	if headerLength < 20 || offset+headerLength > len(f.raw) {
		f.decoded.Malformed = true
		return
	}
	totalLength := int(binary.BigEndian.Uint16(f.raw[offset+2 : offset+4]))
	if totalLength < headerLength || offset+totalLength > len(f.raw) {
		f.decoded.Malformed = true
		return
	}
	f.decoded.IPVersion = 4
	f.decoded.DSCP = f.raw[offset+1] >> 2
	f.decoded.TTL = f.raw[offset+8]
	f.decoded.IPProtocol = f.raw[offset+9]
	f.decoded.SrcIP = formatIPv4(f.raw[offset+12 : offset+16])
	f.decoded.DstIP = formatIPv4(f.raw[offset+16 : offset+20])
	f.offsets[FieldDSCP] = []ByteRange{{Start: offset + 1, End: offset + 2}}
	f.offsets[FieldTTL] = []ByteRange{{Start: offset + 8, End: offset + 9}}
	f.offsets[FieldIPChecksum] = []ByteRange{{Start: offset + 10, End: offset + 12}}
	f.offsets[FieldSrcIP] = []ByteRange{{Start: offset + 12, End: offset + 16}}
	f.offsets[FieldDstIP] = []ByteRange{{Start: offset + 16, End: offset + 20}}
	f.decodeTransport(offset+headerLength, offset+totalLength)
}

func (f *Frame) decodeIPv6(offset int) {
	if offset+40 > len(f.raw) || f.raw[offset]>>4 != 6 {
		f.decoded.Malformed = true
		return
	}
	payloadLength := int(binary.BigEndian.Uint16(f.raw[offset+4 : offset+6]))
	end := offset + 40 + payloadLength
	if end > len(f.raw) {
		f.decoded.Malformed = true
		return
	}
	f.decoded.IPVersion = 6
	f.decoded.DSCP = ((f.raw[offset] & 0x0f) << 2) | (f.raw[offset+1] >> 6)
	f.decoded.IPProtocol = f.raw[offset+6]
	f.decoded.TTL = f.raw[offset+7]
	f.decoded.SrcIP = formatIPv6(f.raw[offset+8 : offset+24])
	f.decoded.DstIP = formatIPv6(f.raw[offset+24 : offset+40])
	f.offsets[FieldDSCP] = []ByteRange{{Start: offset, End: offset + 2}}
	f.offsets[FieldTTL] = []ByteRange{{Start: offset + 7, End: offset + 8}}
	f.offsets[FieldSrcIP] = []ByteRange{{Start: offset + 8, End: offset + 24}}
	f.offsets[FieldDstIP] = []ByteRange{{Start: offset + 24, End: offset + 40}}
	// Extension headers are deliberately not rewritten until the normalized
	// parser can prove their complete chain. They remain observable.
	f.decodeTransport(offset+40, end)
}

func (f *Frame) decodeTransport(offset, end int) {
	if offset < 0 || end < offset || end > len(f.raw) {
		f.decoded.Malformed = true
		return
	}
	switch f.decoded.IPProtocol {
	case uint8(layers.IPProtocolTCP):
		if offset+20 > end {
			f.decoded.Malformed = true
			return
		}
		headerLength := int(f.raw[offset+12]>>4) * 4
		if headerLength < 20 || offset+headerLength > end {
			f.decoded.Malformed = true
			return
		}
		f.decoded.SrcPort = binary.BigEndian.Uint16(f.raw[offset : offset+2])
		f.decoded.DstPort = binary.BigEndian.Uint16(f.raw[offset+2 : offset+4])
		f.decoded.TCPFlags = TCPFlags(f.raw[offset+13]) | TCPFlags(f.raw[offset+12]&1)<<8
		f.offsets[FieldSrcPort] = []ByteRange{{Start: offset, End: offset + 2}}
		f.offsets[FieldDstPort] = []ByteRange{{Start: offset + 2, End: offset + 4}}
		f.offsets[FieldTCPChecksum] = []ByteRange{{Start: offset + 16, End: offset + 18}}
		f.offsets[FieldPayload] = []ByteRange{{Start: offset + headerLength, End: end}}
	case uint8(layers.IPProtocolUDP):
		if offset+8 > end {
			f.decoded.Malformed = true
			return
		}
		length := int(binary.BigEndian.Uint16(f.raw[offset+4 : offset+6]))
		if length < 8 || offset+length > end {
			f.decoded.Malformed = true
			return
		}
		f.decoded.SrcPort = binary.BigEndian.Uint16(f.raw[offset : offset+2])
		f.decoded.DstPort = binary.BigEndian.Uint16(f.raw[offset+2 : offset+4])
		f.offsets[FieldSrcPort] = []ByteRange{{Start: offset, End: offset + 2}}
		f.offsets[FieldDstPort] = []ByteRange{{Start: offset + 2, End: offset + 4}}
		f.offsets[FieldUDPChecksum] = []ByteRange{{Start: offset + 6, End: offset + 8}}
		f.offsets[FieldPayload] = []ByteRange{{Start: offset + 8, End: offset + length}}
	case uint8(layers.IPProtocolICMPv4), uint8(layers.IPProtocolICMPv6):
		if offset+2 > end {
			f.decoded.Malformed = true
			return
		}
		f.decoded.ICMPType = f.raw[offset]
		f.decoded.ICMPCode = f.raw[offset+1]
		f.offsets[FieldPayload] = []ByteRange{{Start: offset + 2, End: end}}
	}
}

func (f *Frame) decodeApplication() {
	packet := gopacket.NewPacket(f.raw, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false, NoCopy: false})
	if packet.ErrorLayer() != nil {
		f.decoded.Malformed = true
	}
	dns, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if dns == nil && (f.decoded.SrcPort == 5353 || f.decoded.DstPort == 5353) {
		if ranges := f.offsets[FieldPayload]; len(ranges) == 1 && ranges[0].Start < ranges[0].End && ranges[0].End <= len(f.raw) {
			decoded := &layers.DNS{}
			if err := decoded.DecodeFromBytes(f.raw[ranges[0].Start:ranges[0].End], gopacket.NilDecodeFeedback); err == nil {
				dns = decoded
			}
		}
	}
	if dns != nil {
		f.decoded.DNSResponse = dns.QR
		for _, question := range dns.Questions {
			if len(f.decoded.DNSNames) == 64 {
				break
			}
			name := strings.TrimSuffix(strings.ToLower(string(question.Name)), ".")
			if name != "" && len(name) <= 255 {
				f.decoded.DNSNames = append(f.decoded.DNSNames, name)
			}
			if f.decoded.DNSType == 0 {
				f.decoded.DNSType = uint16(question.Type)
			}
		}
		if dns.QR {
			records := make([]layers.DNSResourceRecord, 0, len(dns.Answers)+len(dns.Additionals))
			records = append(records, dns.Answers...)
			records = append(records, dns.Additionals...)
			for _, record := range records {
				if len(f.decoded.DNSRecords) == 64 {
					break
				}
				name := boundedDNSName(record.Name)
				if name == "" {
					continue
				}
				answer := DNSRecord{Name: name, Type: uint16(record.Type)}
				switch record.Type {
				case layers.DNSTypeA, layers.DNSTypeAAAA:
					answer.Target = record.IP.String()
				case layers.DNSTypeCNAME:
					answer.Target = boundedDNSName(record.CNAME)
				case layers.DNSTypePTR:
					answer.Target = boundedDNSName(record.PTR)
				case layers.DNSTypeSRV:
					answer.Target = boundedDNSName(record.SRV.Name)
					answer.Port = record.SRV.Port
				default:
					continue
				}
				if answer.Target == "" {
					continue
				}
				f.decoded.DNSRecords = append(f.decoded.DNSRecords, answer)
			}
		}
	}
	payloadRanges := f.offsets[FieldPayload]
	if len(payloadRanges) != 1 || payloadRanges[0].End-payloadRanges[0].Start > 64<<10 {
		return
	}
	r := payloadRanges[0]
	if r.Start == r.End || r.Start < 0 || r.End > len(f.raw) {
		return
	}
	payload := f.raw[r.Start:r.End]
	method, host, path, header := parseHTTPRequest(payload)
	if method != "" {
		f.decoded.HTTPMethod = method
		f.decoded.HTTPHost = host
		f.decoded.HTTPPath = path
		f.decoded.HTTPHeader = header
		return
	}
	status, responseHeader := parseHTTPResponse(payload)
	if status != 0 {
		f.decoded.HTTPStatus = status
		f.decoded.HTTPHeader = responseHeader
	}
}

func parseHTTPRequest(payload []byte) (string, string, string, map[string][]string) {
	reader := bufio.NewReaderSize(bytes.NewReader(payload), min(len(payload)+1, 64<<10))
	req, err := http.ReadRequest(reader)
	if err != nil || req == nil {
		return "", "", "", nil
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	method := strings.ToUpper(req.Method)
	if method == "" || len(method) > 32 || req.URL == nil {
		return "", "", "", nil
	}
	header := boundedHTTPHeaders(req.Header)
	return method, strings.ToLower(req.Host), req.URL.RequestURI(), header
}

func parseHTTPResponse(payload []byte) (uint16, map[string][]string) {
	reader := bufio.NewReaderSize(bytes.NewReader(payload), min(len(payload)+1, 64<<10))
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response == nil || response.StatusCode < 100 || response.StatusCode > 599 {
		return 0, nil
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	return uint16(response.StatusCode), boundedHTTPHeaders(response.Header)
}

func boundedHTTPHeaders(source http.Header) map[string][]string {
	header := make(map[string][]string, len(source))
	for key, values := range source {
		key = http.CanonicalHeaderKey(key)
		if key == "" || len(key) > 128 {
			continue
		}
		for _, value := range values {
			if len(value) <= 8<<10 {
				header[key] = append(header[key], value)
			}
		}
	}
	return header
}

func packetID(f Frame) PacketID {
	h := sha256.New()
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(f.Timestamp.UnixNano()))
	_, _ = h.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(f.Capture.InterfaceIndex))
	_, _ = h.Write(number[:])
	_, _ = h.Write([]byte(f.Capture.Source))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(f.Ingress))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(f.Side))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(f.Direction))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(f.raw)
	return PacketID(hex.EncodeToString(h.Sum(nil)[:16]))
}

func cloneDecoded(in DecodedFields) DecodedFields {
	out := in
	out.VLANs = append([]VLAN(nil), in.VLANs...)
	out.DNSNames = append([]string(nil), in.DNSNames...)
	out.DNSRecords = append([]DNSRecord(nil), in.DNSRecords...)
	if in.HTTPHeader != nil {
		out.HTTPHeader = make(map[string][]string, len(in.HTTPHeader))
		keys := make([]string, 0, len(in.HTTPHeader))
		for key := range in.HTTPHeader {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			out.HTTPHeader[key] = append([]string(nil), in.HTTPHeader[key]...)
		}
	}
	return out
}

func boundedDNSName(value []byte) string {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(string(value))), ".")
	if name == "" || len(name) > 253 {
		return ""
	}
	for _, char := range name {
		if char < 0x20 || char == 0x7f {
			return ""
		}
	}
	return name
}

func normalizeSide(side TopologySide) TopologySide {
	switch side {
	case SideHost, SideSwitch, SideLocal, SideUpstream, SideDownstream:
		return side
	default:
		return SideUnknown
	}
}

func normalizeDirection(direction Direction) Direction {
	switch direction {
	case DirectionHostToSwitch, DirectionSwitchToHost, DirectionInbound, DirectionOutbound:
		return direction
	default:
		return DirectionUnknown
	}
}

func isVLANEtherType(value uint16) bool {
	switch value {
	case 0x8100, 0x88a8, 0x9100:
		return true
	default:
		return false
	}
}

func formatMAC(value []byte) string {
	if len(value) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", value[0], value[1], value[2], value[3], value[4], value[5])
}

func formatIPv4(value []byte) string {
	if len(value) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", value[0], value[1], value[2], value[3])
}

func formatIPv6(value []byte) string {
	if len(value) != 16 {
		return ""
	}
	parts := make([]string, 8)
	for i := range parts {
		parts[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(value[i*2:i*2+2]))
	}
	// net/netip would format compression correctly, but keeping this helper
	// allocation-only avoids retaining an address backed by packet bytes.
	return compressIPv6(parts)
}

func compressIPv6(parts []string) string {
	bestStart, bestLength := -1, 0
	for start := 0; start < len(parts); {
		if parts[start] != "0" {
			start++
			continue
		}
		end := start
		for end < len(parts) && parts[end] == "0" {
			end++
		}
		if end-start > bestLength {
			bestStart, bestLength = start, end-start
		}
		start = end
	}
	if bestLength < 2 {
		return strings.Join(parts, ":")
	}
	left := strings.Join(parts[:bestStart], ":")
	right := strings.Join(parts[bestStart+bestLength:], ":")
	switch {
	case left == "" && right == "":
		return "::"
	case left == "":
		return "::" + right
	case right == "":
		return left + "::"
	default:
		return left + "::" + right
	}
}
