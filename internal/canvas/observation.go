package canvas

// Observation is one sanitized topology update derived from a Network
// session. It contains no packet payload or credential material.
type Observation struct {
	Kind     string
	Adapter  string
	Role     string
	IP       string
	MAC      string
	SrcIP    string
	SrcMAC   string
	DstIP    string
	DstMAC   string
	Protocol string
	Service  string
	Port     uint16
	Tag      string
	Note     string
}
