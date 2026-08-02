package canvas

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// JSONCanvas is the deterministic Obsidian canvas serialization shape.
type JSONCanvas struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Node is one Obsidian canvas node.
type Node struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Color  string `json:"color,omitempty"`
	Text   string `json:"text,omitempty"`
	Label  string `json:"label,omitempty"`
}

// Edge is one Obsidian canvas connection.
type Edge struct {
	ID       string `json:"id"`
	FromNode string `json:"fromNode"`
	FromSide string `json:"fromSide,omitempty"`
	ToNode   string `json:"toNode"`
	ToSide   string `json:"toSide,omitempty"`
	ToEnd    string `json:"toEnd,omitempty"`
	Color    string `json:"color,omitempty"`
	Label    string `json:"label,omitempty"`
}

// JSONCanvas returns a deterministic immutable serialization snapshot.
func (m *Map) JSONCanvas() JSONCanvas {
	hosts := sortedHosts(m.Hosts)
	internal, external, infra := splitHosts(hosts)
	internalCols, externalCols, infraCols := 2, 2, 4
	internalWidth := groupWidth(internalCols)
	externalWidth := groupWidth(externalCols)
	canvasWidth := internalWidth + canvasGroupGap + externalWidth
	infraHeight := groupHeight(len(infra), infraCols)
	mainY := infraHeight + canvasGroupGap
	internalHeight := groupHeight(len(internal), internalCols)
	externalHeight := groupHeight(len(external), externalCols)
	nodes := []Node{
		{ID: "group-infra", Type: "group", X: 0, Y: 0, Width: canvasWidth, Height: infraHeight, Label: "Link / Infrastructure", Color: colorInfra},
		{ID: "group-internal", Type: "group", X: 0, Y: mainY, Width: internalWidth, Height: internalHeight, Label: "Internal", Color: colorInternal},
		{ID: "group-external", Type: "group", X: internalWidth + canvasGroupGap, Y: mainY, Width: externalWidth, Height: externalHeight, Label: "External", Color: colorExternal},
	}

	positions := make(map[string]placedHost)
	addHosts := func(list []*Host, x, y, cols int) {
		for idx, host := range list {
			col := idx % cols
			row := idx / cols
			nx := x + groupPadX + col*(nodeWidth+nodeGapX)
			ny := y + groupTopPad + row*(nodeHeight+nodeGapY)
			positions[host.Key] = placedHost{host: host, x: nx, y: ny}
			nodes = append(nodes, Node{
				ID:     nodeID(host.Key),
				Type:   "text",
				X:      nx,
				Y:      ny,
				Width:  nodeWidth,
				Height: nodeHeight,
				Color:  hostColor(host),
				Text:   hostText(host),
			})
		}
	}
	addHosts(infra, 0, 0, infraCols)
	addHosts(internal, 0, mainY, internalCols)
	addHosts(external, internalWidth+canvasGroupGap, mainY, externalCols)

	var edges []Edge
	conversations := sortedConversations(m.Conversations)
	for _, conv := range conversations {
		if _, ok := m.Hosts[conv.From]; !ok {
			continue
		}
		if _, ok := m.Hosts[conv.To]; !ok {
			continue
		}
		sides := edgeSides(positions[conv.From], positions[conv.To])
		edges = append(edges, Edge{
			ID:       edgeID(conv.Key),
			FromNode: nodeID(conv.From),
			FromSide: sides.from,
			ToNode:   nodeID(conv.To),
			ToSide:   sides.to,
			ToEnd:    "arrow",
			Color:    edgeColor(m.Hosts[conv.From], m.Hosts[conv.To]),
			Label:    convLabel(conv),
		})
	}

	return JSONCanvas{Nodes: nodes, Edges: edges}
}

func nodeID(key string) string {
	return "node-" + shortHash(key)
}

func edgeID(key string) string {
	return "edge-" + shortHash(key)
}

func shortHash(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func hostText(host *Host) string {
	title := firstSorted(host.IPs)
	if title == "" {
		title = firstSorted(host.MACs)
	}
	if title == "" {
		title = strings.TrimPrefix(host.Key, "ip:")
		title = strings.TrimPrefix(title, "mac:")
	}
	var lines []string
	lines = append(lines, "# "+title)
	appendList := func(label string, values []string) {
		if len(values) == 0 {
			return
		}
		lines = append(lines, label+": "+strings.Join(values, ", "))
	}
	appendList("mac", sortedKeys(host.MACs))
	if len(host.IPs) > 1 {
		appendList("ip", sortedKeys(host.IPs))
	}
	appendList("class", sortedKeys(host.Roles))
	appendList("tag", sortedKeys(host.Tags))
	appendList("adapter", sortedKeys(host.Adapters))
	if len(host.Services) > 0 {
		lines = append(lines, "services:")
		for _, service := range sortedServices(host.Services) {
			name := service.Name
			if name == "" {
				name = serviceName(service.Protocol, service.Port)
			}
			lines = append(lines, fmt.Sprintf("- %s/%d %s", strings.ToLower(service.Protocol), service.Port, name))
		}
	}
	appendList("note", sortedKeys(host.Notes))
	return strings.Join(lines, "\n")
}

func hostColor(host *Host) string {
	tags := sortedKeys(host.Tags)
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "self", "local", "debugger":
			return colorSelf
		}
	}
	if hostReference(host) {
		return colorInfra
	}
	if hostInternal(host) {
		return colorInternal
	}
	if len(host.IPs) > 0 {
		return colorExternal
	}
	return colorInfra
}

func edgeColor(from, to *Host) string {
	if from == nil || to == nil {
		return colorInfra
	}
	if hostInternal(from) && hostInternal(to) {
		return colorGreen
	}
	if hostInternal(from) != hostInternal(to) {
		return colorRed
	}
	return colorRed
}

type edgeSidePair struct {
	from string
	to   string
}

func edgeSides(from, to placedHost) edgeSidePair {
	fromCX := from.x + nodeWidth/2
	fromCY := from.y + nodeHeight/2
	toCX := to.x + nodeWidth/2
	toCY := to.y + nodeHeight/2
	dx := toCX - fromCX
	dy := toCY - fromCY
	if abs(dx) >= abs(dy) {
		if dx >= 0 {
			return edgeSidePair{from: "right", to: "left"}
		}
		return edgeSidePair{from: "left", to: "right"}
	}
	if dy >= 0 {
		return edgeSidePair{from: "bottom", to: "top"}
	}
	return edgeSidePair{from: "top", to: "bottom"}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func groupWidth(cols int) int {
	if cols < 1 {
		cols = 1
	}
	return groupPadX*2 + cols*nodeWidth + (cols-1)*nodeGapX
}

func groupHeight(count, cols int) int {
	if cols < 1 {
		cols = 1
	}
	rows := (count + cols - 1) / cols
	if rows < 1 {
		rows = 1
	}
	return groupTopPad + rows*nodeHeight + (rows-1)*nodeGapY + groupBottomPad
}
