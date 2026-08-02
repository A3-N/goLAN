// Package recording owns the paired original/forwarded PCAP recorder shared
// by packet-forwarding data planes.
package recording

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golan/internal/policy"
	"golan/internal/syncgate"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PairRecorder writes original packets, forwarded packets, and their decision
// journal as one serialized evidence stream.
type PairRecorder struct {
	gate            syncgate.Gate
	originalFile    *os.File
	forwardedFile   *os.File
	originalWriter  *pcapgo.Writer
	forwardedWriter *pcapgo.Writer
	journal         *policy.Journal
	originalCount   uint64
	forwardedCount  uint64
}

// OpenPair creates an exclusive evidence pair in directory. Context is a
// short data-plane label used only in errors.
func OpenPair(directory string, linkType layers.LinkType, contextLabel string) (*PairRecorder, error) {
	contextLabel = strings.TrimSpace(contextLabel)
	if contextLabel == "" {
		contextLabel = "packet"
	}
	originalPath := filepath.Join(directory, "original.pcap")
	forwardedPath := filepath.Join(directory, "forwarded.pcap")
	originalFile, err := os.OpenFile(originalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create original pcap: %w", err)
	}
	originalWriter := pcapgo.NewWriter(originalFile)
	if err := originalWriter.WriteFileHeader(65535, linkType); err != nil {
		return nil, errors.Join(fmt.Errorf("write original pcap header: %w", err), discardCreatedArtifacts(
			[]*os.File{originalFile}, []string{originalPath},
		))
	}
	forwardedFile, err := os.OpenFile(forwardedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create forwarded pcap: %w", err), discardCreatedArtifacts(
			[]*os.File{originalFile}, []string{originalPath},
		))
	}
	forwardedWriter := pcapgo.NewWriter(forwardedFile)
	if err := forwardedWriter.WriteFileHeader(65535, linkType); err != nil {
		return nil, errors.Join(fmt.Errorf("write forwarded pcap header: %w", err), discardCreatedArtifacts(
			[]*os.File{originalFile, forwardedFile}, []string{originalPath, forwardedPath},
		))
	}
	journal, err := policy.OpenJournal(filepath.Join(directory, "decisions.jsonl"))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open %s decision journal: %w", contextLabel, err), discardCreatedArtifacts(
			[]*os.File{originalFile, forwardedFile}, []string{originalPath, forwardedPath},
		))
	}
	return &PairRecorder{
		originalFile: originalFile, forwardedFile: forwardedFile,
		originalWriter: originalWriter, forwardedWriter: forwardedWriter,
		journal: journal,
	}, nil
}

// WriteOriginal appends one packet and returns its one-based ordinal.
func (recorder *PairRecorder) WriteOriginal(info gopacket.CaptureInfo, data []byte) (uint64, error) {
	release := recorder.gate.Enter()
	defer release()
	if err := recorder.originalWriter.WritePacket(info, data); err != nil {
		return 0, fmt.Errorf("write original pcap: %w", err)
	}
	recorder.originalCount++
	return recorder.originalCount, nil
}

// WriteForwarded appends one packet and returns its one-based ordinal.
func (recorder *PairRecorder) WriteForwarded(info gopacket.CaptureInfo, data []byte) (uint64, error) {
	release := recorder.gate.Enter()
	defer release()
	if err := recorder.forwardedWriter.WritePacket(info, data); err != nil {
		return 0, fmt.Errorf("write forwarded pcap: %w", err)
	}
	recorder.forwardedCount++
	return recorder.forwardedCount, nil
}

// WriteDecision appends one payload-free decision record.
func (recorder *PairRecorder) WriteDecision(decision policy.Decision) error {
	return recorder.journal.Append(decision)
}

// Close flushes and closes every evidence stream.
func (recorder *PairRecorder) Close() error {
	if recorder == nil {
		return nil
	}
	release := recorder.gate.Enter()
	defer release()
	return errors.Join(
		recorder.journal.Close(),
		syncFile(recorder.originalFile, "original pcap"),
		syncFile(recorder.forwardedFile, "forwarded pcap"),
	)
}

func discardCreatedArtifacts(files []*os.File, paths []string) error {
	var errs []error
	for _, file := range files {
		if file != nil {
			if err := file.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close incomplete %s: %w", filepath.Base(file.Name()), err))
			}
		}
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove incomplete %s: %w", filepath.Base(path), err))
		}
	}
	return errors.Join(errs...)
}

func syncFile(file *os.File, name string) error {
	if file == nil {
		return nil
	}
	var errs []error
	if err := file.Sync(); err != nil {
		errs = append(errs, fmt.Errorf("sync %s: %w", name, err))
	}
	if err := file.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close %s: %w", name, err))
	}
	return errors.Join(errs...)
}
