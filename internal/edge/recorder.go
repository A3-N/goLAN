package edge

import (
	"golan/internal/recording"

	"github.com/google/gopacket/layers"
)

type recorder = recording.PairRecorder

func openRecorder(directory string, linkType layers.LinkType) (*recorder, error) {
	return recording.OpenPair(directory, linkType, "edge")
}
