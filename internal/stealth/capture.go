package stealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// CaptureOptions controls passive packet capture file output.
type CaptureOptions struct {
	Dir      string
	MaxBytes int64
}

// StartPacketCapture starts a best-effort passive pcap writer for an interface.
// It never injects traffic; failures are reported to the caller and then ignored
// by bridge setup so forwarding is not blocked by diagnostics.
func StartPacketCapture(ctx context.Context, iface string, opts CaptureOptions, eventLog func(string)) (string, error) {
	if eventLog == nil {
		eventLog = func(string) {}
	}
	if iface == "" {
		return "", fmt.Errorf("empty capture interface")
	}
	if opts.Dir == "" {
		opts.Dir = "/tmp/golan-pcaps"
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 128 * 1024 * 1024
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return "", fmt.Errorf("creating pcap directory: %w", err)
	}

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return "", fmt.Errorf("opening %s for pcap capture: %w", iface, err)
	}

	stamp := time.Now().Format("20060102-150405")
	path := filepath.Join(opts.Dir, fmt.Sprintf("golan-%s-%s.pcap", safeCaptureName(iface), stamp))
	file, err := os.Create(path)
	if err != nil {
		handle.Close()
		return "", fmt.Errorf("creating pcap file: %w", err)
	}

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		handle.Close()
		file.Close()
		return "", fmt.Errorf("writing pcap header: %w", err)
	}

	go func() {
		defer handle.Close()
		defer file.Close()

		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				handle.Close()
			case <-done:
			}
		}()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packets := packetSource.Packets()
		var written int64

		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-packets:
				if packet == nil {
					return
				}
				data := packet.Data()
				if opts.MaxBytes > 0 && written+int64(len(data)) > opts.MaxBytes {
					eventLog(fmt.Sprintf("[*][PCAP] Capture cap reached on %s: %s", iface, path))
					return
				}
				if err := writer.WritePacket(packet.Metadata().CaptureInfo, data); err != nil {
					eventLog(fmt.Sprintf("[W][PCAP] Capture stopped on %s: %v", iface, err))
					return
				}
				written += int64(len(data))
			}
		}
	}()

	return path, nil
}

func safeCaptureName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return replacer.Replace(name)
}
