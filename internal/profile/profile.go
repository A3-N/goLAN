package profile

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golan/internal/adapters"
)

// MaxAdapters is the host/switch pair supported by one inline profile.
const MaxAdapters = 2

// Inline adapter roles identify the host and switch sides.
const (
	AdapterRoleHost   = "host"
	AdapterRoleSwitch = "switch"
)

// FieldDef describes an editable adapter setup property.
type FieldDef struct {
	Key   string
	Label string
	Hint  string
}

var fieldDefinitions = [...]FieldDef{
	{Key: "label", Label: "Label", Hint: "display name for this setup"},
	{Key: "role", Label: "Role", Hint: "optional host-side or switch-side purpose"},
	{Key: "ip", Label: "IP", Hint: "static IPv4 address or auto"},
	{Key: "cidr", Label: "CIDR", Hint: "optional prefix length"},
	{Key: "gateway", Label: "Gateway", Hint: "optional gateway address"},
	{Key: "dns", Label: "DNS", Hint: "comma-separated DNS servers"},
	{Key: "mtu", Label: "MTU", Hint: "desired MTU"},
	{Key: "mac", Label: "MAC", Hint: "desired MAC override"},
	{Key: "dhcp", Label: "DHCP", Hint: "auto, manual, off"},
	{Key: "state", Label: "State", Hint: "auto, up, down"},
	{Key: "notes", Label: "Notes", Hint: "free-form setup note"},
}

// Fields returns an immutable snapshot of the ordered TUI edit surface.
func Fields() []FieldDef {
	return append([]FieldDef(nil), fieldDefinitions[:]...)
}

// AdapterConfig holds the selected adapter and optional desired values.
type AdapterConfig struct {
	AdapterRole  string `json:"role"`
	Name         string `json:"name"`
	HardwarePort string `json:"hardware_port"`
	// NetworkService is rehydrated from live macOS discovery and deliberately
	// excluded from persisted configs because users can rename it at any time.
	NetworkService string   `json:"-"`
	Kind           string   `json:"kind"`
	CurrentMAC     string   `json:"current_mac"`
	CurrentMTU     int      `json:"current_mtu"`
	Addrs          []string `json:"addrs,omitempty"`

	Label   string `json:"label"`
	Role    string `json:"option_role"`
	IP      string `json:"ip"`
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway"`
	DNS     string `json:"dns"`
	MTU     string `json:"mtu"`
	MAC     string `json:"mac"`
	DHCP    string `json:"dhcp"`
	State   string `json:"state"`
	Notes   string `json:"notes"`

	Discovered []DiscoveredValue `json:"discovered,omitempty"`
}

// DiscoveredValue is passive traffic evidence that may fill an auto setting.
type DiscoveredValue struct {
	Field     string    `json:"field"`
	Value     string    `json:"value"`
	Evidence  string    `json:"evidence"`
	Packet    string    `json:"packet"`
	FirstSeen time.Time `json:"first_seen"`
	Count     int       `json:"count"`
}

// BridgeConfig holds passive observations that describe the link/bridge view.
type BridgeConfig struct {
	Config       AdapterConfig       `json:"config"`
	Observations []BridgeObservation `json:"observations,omitempty"`
}

// BridgeObservation is traffic evidence not owned by one adapter property.
type BridgeObservation struct {
	Adapter   string    `json:"adapter"`
	Role      string    `json:"role"`
	Field     string    `json:"field"`
	Value     string    `json:"value"`
	Evidence  string    `json:"evidence"`
	Packet    string    `json:"packet"`
	FirstSeen time.Time `json:"first_seen"`
	Count     int       `json:"count"`
}

// Profile is the staged initialization state.
type Profile struct {
	Adapters []AdapterConfig
	Bridge   BridgeConfig `json:"bridge"`
}

// FromAdapter creates the default staged config for a selected adapter.
func FromAdapter(adapterRole string, adapter adapters.Adapter) AdapterConfig {
	adapterRole = CanonicalAdapterRole(adapterRole)
	cfg := AdapterConfig{
		AdapterRole:    adapterRole,
		Name:           adapter.Name,
		HardwarePort:   adapter.HardwarePort,
		NetworkService: adapter.NetworkService,
		Kind:           adapter.Kind,
		CurrentMAC:     adapter.MAC,
		CurrentMTU:     adapter.MTU,
		Addrs:          append([]string(nil), adapter.Addrs...),
	}
	ensureEditableDefaults(&cfg)
	return cfg
}

// Ready reports whether the staged setup has a valid adapter count.
func (p Profile) Ready() bool {
	return len(p.Adapters) >= 1 && len(p.Adapters) <= MaxAdapters
}

// Rehydrate validates a persisted profile and replaces stored platform
// metadata with values from the current adapter inventory. Editable values and
// passive evidence are preserved only after validation.
func Rehydrate(saved Profile, inventory []adapters.Adapter) (Profile, error) {
	if len(saved.Adapters) == 0 {
		return Profile{}, fmt.Errorf("profile has no adapters")
	}
	if len(saved.Adapters) > MaxAdapters {
		return Profile{}, fmt.Errorf("profile has %d adapters; maximum is %d", len(saved.Adapters), MaxAdapters)
	}

	liveByName := make(map[string]adapters.Adapter, len(inventory))
	for _, adapter := range inventory {
		name := strings.ToLower(strings.TrimSpace(adapter.Name))
		if name != "" {
			liveByName[name] = adapter
		}
	}

	var out Profile
	seenNames := make(map[string]bool, len(saved.Adapters))
	seenRoles := make(map[string]bool, len(saved.Adapters))
	for _, stored := range saved.Adapters {
		name := strings.ToLower(strings.TrimSpace(stored.Name))
		if name == "" {
			return Profile{}, fmt.Errorf("profile adapter name is required")
		}
		if seenNames[name] {
			return Profile{}, fmt.Errorf("profile adapter %q is duplicated", stored.Name)
		}
		seenNames[name] = true

		adapterRole := CanonicalAdapterRole(stored.AdapterRole)
		if !ValidAdapterRole(adapterRole) {
			return Profile{}, fmt.Errorf("profile adapter %q has invalid role %q", stored.Name, stored.AdapterRole)
		}
		if seenRoles[adapterRole] {
			return Profile{}, fmt.Errorf("profile role %q is duplicated", adapterRole)
		}
		seenRoles[adapterRole] = true

		live, ok := liveByName[name]
		if !ok {
			return Profile{}, fmt.Errorf("profile adapter %q is not present", stored.Name)
		}
		cfg := FromAdapter(adapterRole, live)
		if err := copyEditableValues(&cfg, stored); err != nil {
			return Profile{}, fmt.Errorf("profile adapter %q: %w", stored.Name, err)
		}
		discovered, err := validateDiscoveries(stored.Discovered)
		if err != nil {
			return Profile{}, fmt.Errorf("profile adapter %q: %w", stored.Name, err)
		}
		cfg.Discovered = discovered
		out.Adapters = append(out.Adapters, cfg)
	}
	out.sortRoles()

	bridgeCfg := AdapterConfig{}
	ensureBridgeAdapterDefaults(&bridgeCfg)
	if err := copyEditableValues(&bridgeCfg, saved.Bridge.Config); err != nil {
		return Profile{}, fmt.Errorf("bridge config: %w", err)
	}
	out.Bridge.Config = bridgeCfg
	observations, err := validateBridgeObservations(saved.Bridge.Observations)
	if err != nil {
		return Profile{}, err
	}
	out.Bridge.Observations = observations
	return out, nil
}

// Role returns a mutable selected adapter config by adapter role.
func (p *Profile) Role(adapterRole string) (*AdapterConfig, bool) {
	adapterRole = CanonicalAdapterRole(adapterRole)
	for i := range p.Adapters {
		if p.Adapters[i].AdapterRole == adapterRole {
			return &p.Adapters[i], true
		}
	}
	return nil, false
}

// SelectedRole returns the role for an adapter name.
func (p Profile) SelectedRole(name string) (string, bool) {
	for _, adapter := range p.Adapters {
		if strings.EqualFold(adapter.Name, name) {
			return adapter.AdapterRole, true
		}
	}
	return "", false
}

// ByName returns a mutable selected adapter config by interface name.
func (p *Profile) ByName(name string) (*AdapterConfig, bool) {
	for i := range p.Adapters {
		if strings.EqualFold(p.Adapters[i].Name, name) {
			return &p.Adapters[i], true
		}
	}
	return nil, false
}

// Add stages an adapter in the next available role.
func (p *Profile) Add(adapter adapters.Adapter) (AdapterConfig, error) {
	if _, ok := p.SelectedRole(adapter.Name); ok {
		return AdapterConfig{}, fmt.Errorf("%s is already selected", adapter.Name)
	}
	adapterRole, ok := p.nextAvailableRole()
	if !ok {
		return AdapterConfig{}, fmt.Errorf("maximum of %d adapters already selected", MaxAdapters)
	}

	cfg := FromAdapter(adapterRole, adapter)
	p.Adapters = append(p.Adapters, cfg)
	p.sortRoles()
	return cfg, nil
}

// SetAdapterRole stages an adapter in a specific role, replacing that role if needed.
func (p *Profile) SetAdapterRole(adapter adapters.Adapter, adapterRole string) (AdapterConfig, error) {
	adapterRole = CanonicalAdapterRole(adapterRole)
	if !ValidAdapterRole(adapterRole) {
		return AdapterConfig{}, fmt.Errorf("role must be host or switch")
	}

	var previous *AdapterConfig
	for _, current := range p.Adapters {
		if strings.EqualFold(current.Name, adapter.Name) {
			copy := current
			previous = &copy
			break
		}
	}
	cfg := FromAdapter(adapterRole, adapter)
	if previous != nil {
		if err := copyEditableValues(&cfg, *previous); err != nil {
			return AdapterConfig{}, fmt.Errorf("preserve adapter settings: %w", err)
		}
		cfg.Discovered = append([]DiscoveredValue(nil), previous.Discovered...)
	}

	for i := 0; i < len(p.Adapters); i++ {
		if strings.EqualFold(p.Adapters[i].Name, adapter.Name) || p.Adapters[i].AdapterRole == adapterRole {
			p.Adapters = append(p.Adapters[:i], p.Adapters[i+1:]...)
			i--
		}
	}

	p.Adapters = append(p.Adapters, cfg)
	p.sortRoles()
	return cfg, nil
}

// RemoveName removes a staged adapter by interface name.
func (p *Profile) RemoveName(name string) (AdapterConfig, bool) {
	for i, adapter := range p.Adapters {
		if strings.EqualFold(adapter.Name, name) {
			removed := adapter
			p.Adapters = append(p.Adapters[:i], p.Adapters[i+1:]...)
			return removed, true
		}
	}
	return AdapterConfig{}, false
}

// RemoveRole removes a staged adapter by role.
func (p *Profile) RemoveRole(adapterRole string) (AdapterConfig, bool) {
	adapterRole = CanonicalAdapterRole(adapterRole)
	for i, adapter := range p.Adapters {
		if adapter.AdapterRole == adapterRole {
			removed := adapter
			p.Adapters = append(p.Adapters[:i], p.Adapters[i+1:]...)
			return removed, true
		}
	}
	return AdapterConfig{}, false
}

// Reset clears all staged adapters.
func (p *Profile) Reset() {
	p.Adapters = nil
	p.Bridge = BridgeConfig{}
}

// BridgeAdapter returns the editable bridge-level takeover config.
func (p *Profile) BridgeAdapter() *AdapterConfig {
	ensureBridgeAdapterDefaults(&p.Bridge.Config)
	return &p.Bridge.Config
}

// BridgeAdapterSnapshot returns a copy of the editable bridge-level config.
func (p Profile) BridgeAdapterSnapshot() AdapterConfig {
	ensureBridgeAdapterDefaults(&p.Bridge.Config)
	return p.Bridge.Config
}

// AddBridgeObservation records passive link-level evidence.
func (p *Profile) AddBridgeObservation(adapter, role, field, value, evidence, packet string) bool {
	field = canonicalKey(field)
	value = strings.TrimSpace(value)
	if field == "" || value == "" {
		return false
	}

	now := time.Now().UTC()
	for i := range p.Bridge.Observations {
		obs := &p.Bridge.Observations[i]
		if strings.EqualFold(obs.Adapter, adapter) &&
			strings.EqualFold(obs.Role, role) &&
			canonicalKey(obs.Field) == field &&
			strings.EqualFold(obs.Value, value) &&
			obs.Evidence == evidence &&
			obs.Packet == packet {
			obs.Count++
			return false
		}
	}

	p.Bridge.Observations = append(p.Bridge.Observations, BridgeObservation{
		Adapter:   adapter,
		Role:      role,
		Field:     field,
		Value:     value,
		Evidence:  evidence,
		Packet:    packet,
		FirstSeen: now,
		Count:     1,
	})
	return true
}

func (p Profile) nextAvailableRole() (string, bool) {
	for _, adapterRole := range []string{AdapterRoleHost, AdapterRoleSwitch} {
		if _, ok := p.Role(adapterRole); !ok {
			return adapterRole, true
		}
	}
	return "", false
}

func (p *Profile) sortRoles() {
	for i := 0; i < len(p.Adapters); i++ {
		for j := i + 1; j < len(p.Adapters); j++ {
			if roleRank(p.Adapters[j].AdapterRole) < roleRank(p.Adapters[i].AdapterRole) {
				p.Adapters[i], p.Adapters[j] = p.Adapters[j], p.Adapters[i]
			}
		}
	}
}

// CanonicalAdapterRole normalizes a user-facing inline adapter role.
func CanonicalAdapterRole(adapterRole string) string {
	switch strings.ToLower(strings.TrimSpace(adapterRole)) {
	case "1", "host":
		return AdapterRoleHost
	case "2", "switch":
		return AdapterRoleSwitch
	default:
		return strings.ToLower(strings.TrimSpace(adapterRole))
	}
}

// ValidAdapterRole reports whether adapterRole identifies an inline side.
func ValidAdapterRole(adapterRole string) bool {
	switch CanonicalAdapterRole(adapterRole) {
	case AdapterRoleHost, AdapterRoleSwitch:
		return true
	default:
		return false
	}
}

// AdapterRoles returns the valid roles in stable host/switch order.
func AdapterRoles() []string {
	return []string{AdapterRoleHost, AdapterRoleSwitch}
}

func ensureBridgeAdapterDefaults(cfg *AdapterConfig) {
	if strings.TrimSpace(cfg.AdapterRole) == "" {
		cfg.AdapterRole = "bridge"
	}
	if strings.TrimSpace(cfg.Name) == "" {
		cfg.Name = "bridge"
	}
	if strings.TrimSpace(cfg.Kind) == "" {
		cfg.Kind = "bridge"
	}
	ensureEditableDefaults(cfg)
}

func ensureEditableDefaults(cfg *AdapterConfig) {
	for _, value := range []*string{
		&cfg.Label,
		&cfg.Role,
		&cfg.IP,
		&cfg.CIDR,
		&cfg.Gateway,
		&cfg.DNS,
		&cfg.MTU,
		&cfg.MAC,
		&cfg.DHCP,
		&cfg.State,
		&cfg.Notes,
	} {
		if strings.TrimSpace(*value) == "" {
			*value = "auto"
		}
	}
}

func roleRank(adapterRole string) int {
	switch CanonicalAdapterRole(adapterRole) {
	case AdapterRoleHost:
		return 1
	case AdapterRoleSwitch:
		return 2
	default:
		return 99
	}
}

// Value returns a field value by key.
func (c AdapterConfig) Value(key string) string {
	switch canonicalKey(key) {
	case "label":
		return c.Label
	case "role":
		return c.Role
	case "ip":
		return c.IP
	case "cidr":
		return c.CIDR
	case "gateway":
		return c.Gateway
	case "dns":
		return c.DNS
	case "mtu":
		return c.MTU
	case "mac":
		return c.MAC
	case "dhcp":
		return c.DHCP
	case "state":
		return c.State
	case "notes":
		return c.Notes
	default:
		return ""
	}
}

// Values returns all explicit and discovered values for autocomplete.
func (c AdapterConfig) Values(key string) []string {
	key = canonicalKey(key)
	out := []string{}
	if value := c.Value(key); value != "" {
		out = appendUnique(out, value)
	}
	for _, discovered := range c.Discovered {
		if canonicalKey(discovered.Field) == key {
			out = appendUnique(out, discovered.Value)
		}
	}
	return out
}

// Set updates one optional property and returns the previous value.
func (c *AdapterConfig) Set(key, value string) (string, error) {
	key = canonicalKey(key)
	value = strings.TrimSpace(value)
	if value == "" {
		value = "auto"
	}
	if err := validate(key, value); err != nil {
		return "", err
	}

	old := c.Value(key)
	switch key {
	case "label":
		c.Label = value
	case "role":
		c.Role = value
	case "ip":
		c.IP = value
	case "cidr":
		c.CIDR = value
	case "gateway":
		c.Gateway = value
	case "dns":
		c.DNS = normalizeCSV(value)
	case "mtu":
		c.MTU = value
	case "mac":
		c.MAC = strings.ToLower(value)
	case "dhcp":
		c.DHCP = strings.ToLower(value)
	case "state":
		c.State = strings.ToLower(value)
	case "notes":
		c.Notes = value
	default:
		return "", fmt.Errorf("unknown property %q", key)
	}
	return old, nil
}

// Clear empties one optional property.
func (c *AdapterConfig) Clear(key string) (string, error) {
	return c.Set(key, "auto")
}

// AddDiscovery records passive traffic evidence and fills auto values.
func (c *AdapterConfig) AddDiscovery(field, value, evidence, packet string) (bool, bool) {
	field = canonicalKey(field)
	value = strings.TrimSpace(value)
	if field == "" || value == "" {
		return false, false
	}

	now := time.Now().UTC()
	for i := range c.Discovered {
		if canonicalKey(c.Discovered[i].Field) == field &&
			strings.EqualFold(c.Discovered[i].Value, value) &&
			c.Discovered[i].Evidence == evidence &&
			c.Discovered[i].Packet == packet {
			c.Discovered[i].Count++
			applied := false
			if strings.EqualFold(c.Value(field), "auto") {
				_, err := c.Set(field, value)
				applied = err == nil
			}
			return false, applied
		}
	}

	c.Discovered = append(c.Discovered, DiscoveredValue{
		Field:     field,
		Value:     value,
		Evidence:  evidence,
		Packet:    packet,
		FirstSeen: now,
		Count:     1,
	})

	applied := false
	if strings.EqualFold(c.Value(field), "auto") {
		_, err := c.Set(field, value)
		applied = err == nil
	}
	return true, applied
}

// ApplyFirstDiscovery fills an auto field from the oldest saved discovery.
func (c *AdapterConfig) ApplyFirstDiscovery(field string) (string, bool) {
	field = canonicalKey(field)
	if !strings.EqualFold(c.Value(field), "auto") {
		return "", false
	}
	for _, discovered := range c.Discovered {
		if canonicalKey(discovered.Field) != field {
			continue
		}
		if _, err := c.Set(field, discovered.Value); err == nil {
			return discovered.Value, true
		}
	}
	return "", false
}

// SummaryLines returns a compact setup summary.
func (p Profile) SummaryLines() []string {
	if len(p.Adapters) == 0 {
		return []string{"no adapters selected"}
	}

	lines := make([]string, 0, len(p.Adapters))
	for _, adapter := range p.Adapters {
		label := adapter.Name
		if !isAuto(adapter.Label) {
			label += " (" + adapter.Label + ")"
		}
		details := []string{adapter.AdapterRole, label}
		if !isAuto(adapter.Role) {
			details = append(details, "role="+adapter.Role)
		}
		if !isAuto(adapter.IP) {
			details = append(details, "ip="+adapter.IP)
		}
		if !isAuto(adapter.MTU) {
			details = append(details, "mtu="+adapter.MTU)
		}
		if !isAuto(adapter.State) {
			details = append(details, "state="+adapter.State)
		}
		lines = append(lines, strings.Join(details, " "))
	}
	return lines
}

func validate(key, value string) error {
	key = canonicalKey(key)
	if !knownField(key) {
		return fmt.Errorf("unknown property %q", key)
	}
	if isAuto(value) {
		return nil
	}

	switch key {
	case "label", "role", "notes":
		return nil
	case "ip", "gateway":
		if net.ParseIP(value).To4() == nil {
			return fmt.Errorf("%s must be an IPv4 address", key)
		}
	case "cidr":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 32 {
			return fmt.Errorf("cidr must be between 0 and 32")
		}
	case "dns":
		for _, entry := range strings.Split(value, ",") {
			if net.ParseIP(strings.TrimSpace(entry)) == nil {
				return fmt.Errorf("dns entries must be IP addresses")
			}
		}
	case "mtu":
		n, err := strconv.Atoi(value)
		if err != nil || n < 68 || n > 9216 {
			return fmt.Errorf("mtu must be between 68 and 9216")
		}
	case "mac":
		mac, err := net.ParseMAC(value)
		if err != nil || !validUnicastMAC(mac) {
			return fmt.Errorf("mac must be a usable 48-bit unicast address")
		}
	case "dhcp":
		switch strings.ToLower(value) {
		case "auto", "manual", "off":
		default:
			return fmt.Errorf("dhcp must be auto, manual, or off")
		}
	case "state":
		switch strings.ToLower(value) {
		case "auto", "up", "down":
		default:
			return fmt.Errorf("state must be auto, up, or down")
		}
	default:
		return fmt.Errorf("unknown property %q", key)
	}
	return nil
}

func copyEditableValues(dst *AdapterConfig, src AdapterConfig) error {
	for _, field := range fieldDefinitions {
		value := strings.TrimSpace(src.Value(field.Key))
		if value == "" {
			continue
		}
		if _, err := dst.Set(field.Key, value); err != nil {
			return fmt.Errorf("%s: %w", field.Key, err)
		}
	}
	return nil
}

func validateDiscoveries(values []DiscoveredValue) ([]DiscoveredValue, error) {
	out := make([]DiscoveredValue, 0, len(values))
	for _, value := range values {
		value.Field = canonicalKey(value.Field)
		value.Value = strings.TrimSpace(value.Value)
		if !knownField(value.Field) || value.Value == "" {
			return nil, fmt.Errorf("invalid discovery field %q", value.Field)
		}
		if err := validate(value.Field, value.Value); err != nil {
			return nil, fmt.Errorf("discovery %s: %w", value.Field, err)
		}
		if value.Count < 1 {
			value.Count = 1
		}
		out = append(out, value)
	}
	return out, nil
}

func validateBridgeObservations(values []BridgeObservation) ([]BridgeObservation, error) {
	out := make([]BridgeObservation, 0, len(values))
	for _, value := range values {
		value.Adapter = strings.TrimSpace(value.Adapter)
		value.Role = strings.TrimSpace(value.Role)
		value.Field = canonicalKey(value.Field)
		value.Value = strings.TrimSpace(value.Value)
		if value.Adapter == "" || value.Field == "" || value.Value == "" {
			return nil, fmt.Errorf("bridge observation is incomplete")
		}
		if value.Count < 1 {
			value.Count = 1
		}
		out = append(out, value)
	}
	return out, nil
}

func validUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, octet := range mac {
		if octet != 0 {
			return true
		}
	}
	return false
}

func knownField(key string) bool {
	key = canonicalKey(key)
	for _, field := range fieldDefinitions {
		if field.Key == key {
			return true
		}
	}
	return false
}

func normalizeCSV(value string) string {
	if isAuto(value) {
		return "auto"
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, ", ")
}

// CanonicalKey maps user-facing command aliases to stored property names.
func CanonicalKey(key string) string {
	return canonicalKey(key)
}

// KnownField reports whether key is an adapter property.
func KnownField(key string) bool {
	return knownField(key)
}

func canonicalKey(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "ipv4", "addr", "address":
		return "ip"
	case "link":
		return "state"
	default:
		return strings.ToLower(strings.TrimSpace(key))
	}
}

func isAuto(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "auto")
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}
