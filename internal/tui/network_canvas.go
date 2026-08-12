package tui

import (
	"fmt"

	"golan/internal/canvas"
	networkobs "golan/internal/network"
)

func (m *Model) buildNetworkCanvas(args []string) {
	if len(args) > 1 {
		m.print("use: canvas build [network-session-id]")
		return
	}
	var session networkobs.Session
	if len(args) == 1 {
		if m.project == nil {
			m.print("canvas err: open a project to select a saved Network session")
			return
		}
		loaded, _, err := m.project.ReadNetworkSession(args[0])
		if err != nil {
			m.print("canvas err: " + err.Error())
			return
		}
		session = loaded
	} else if m.networkTracker != nil {
		session = m.networkTracker.Snapshot()
	} else {
		m.print("canvas err: no Network observations are available")
		return
	}

	generated := canvas.FromNetworkSession(session)
	m.canvasMap = generated
	m.canvasDirty = true
	m.print(fmt.Sprintf("canvas: built from network session=%s devices=%d hosts=%d links=%d", session.ID, len(session.Devices), len(generated.Hosts), len(generated.Conversations)))
}
