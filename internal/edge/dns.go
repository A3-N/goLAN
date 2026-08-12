package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	dnsPort            = 53
	dnsExchangeTimeout = 4 * time.Second
	dnsMaxMessage      = 65535
	dnsMaxConcurrent   = 128
)

// dnsRelay exposes a loopback DNS proxy to the downstream host without ever
// advertising 127/8 to that host. It deliberately binds only to Edge's
// downstream gateway address.
type dnsRelay struct {
	udp       *net.UDPConn
	tcp       *net.TCPListener
	upstreams []netip.AddrPort
	closeOnce sync.Once
	mu        sync.Mutex
	clients   map[net.Conn]bool
	handlers  sync.WaitGroup
}

func requiresDNSRelay(addresses []netip.Addr) bool {
	for _, address := range addresses {
		if address.IsLoopback() {
			return true
		}
	}
	return false
}

func relayLeaseDNS(lease Lease, upstreams []netip.Addr) Lease {
	if requiresDNSRelay(upstreams) {
		lease.DNS = []netip.Addr{lease.ServerIP}
	}
	return lease
}

func startDNSRelay(server netip.Addr, upstreams []netip.Addr) (*dnsRelay, error) {
	if !server.Is4() || server.IsUnspecified() {
		return nil, fmt.Errorf("DNS relay requires a usable IPv4 listen address")
	}
	addresses := make([]netip.AddrPort, 0, len(upstreams))
	for _, address := range upstreams {
		if !usableDNSAddress(address) {
			return nil, fmt.Errorf("DNS relay upstream %s is not usable IPv4", address)
		}
		addresses = append(addresses, netip.AddrPortFrom(address, dnsPort))
	}
	return listenDNSRelay(netip.AddrPortFrom(server, dnsPort), addresses)
}

func listenDNSRelay(listenAddress netip.AddrPort, upstreams []netip.AddrPort) (*dnsRelay, error) {
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("DNS relay requires at least one upstream")
	}
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listenAddress))
	if err != nil {
		return nil, fmt.Errorf("listen for downstream UDP DNS on %s: %w", listenAddress, err)
	}
	if listenAddress.Port() == 0 {
		listenAddress = udp.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	tcp, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(listenAddress))
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listen for downstream TCP DNS on %s: %w", listenAddress, err)
	}
	return &dnsRelay{
		udp: udp, tcp: tcp, upstreams: append([]netip.AddrPort(nil), upstreams...),
		clients: make(map[net.Conn]bool),
	}, nil
}

func (relay *dnsRelay) Run(ctx context.Context) error {
	if relay == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	errCh := make(chan error, 2)
	go func() { errCh <- relay.serveUDP(ctx) }()
	go func() { errCh <- relay.serveTCP(ctx) }()
	go func() {
		<-ctx.Done()
		_ = relay.Close()
	}()
	first := <-errCh
	_ = relay.Close()
	second := <-errCh
	relay.handlers.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(first, second)
}

func (relay *dnsRelay) Close() error {
	if relay == nil {
		return nil
	}
	var closeErr error
	relay.closeOnce.Do(func() {
		closeErr = errors.Join(relay.udp.Close(), relay.tcp.Close())
		relay.mu.Lock()
		for client := range relay.clients {
			closeErr = errors.Join(closeErr, client.Close())
		}
		relay.mu.Unlock()
	})
	return closeErr
}

func (relay *dnsRelay) serveUDP(ctx context.Context) error {
	semaphore := make(chan struct{}, dnsMaxConcurrent)
	buffer := make([]byte, dnsMaxMessage)
	for {
		count, client, err := relay.udp.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read downstream UDP DNS: %w", err)
		}
		query := append([]byte(nil), buffer[:count]...)
		select {
		case semaphore <- struct{}{}:
			relay.handlers.Add(1)
			go func() {
				defer relay.handlers.Done()
				defer func() { <-semaphore }()
				response, exchangeErr := relay.exchangeUDP(ctx, query)
				if exchangeErr != nil {
					response = dnsServerFailure(query)
				}
				if len(response) > 0 {
					_, _ = relay.udp.WriteToUDPAddrPort(response, client)
				}
			}()
		default:
			if response := dnsServerFailure(query); len(response) > 0 {
				_, _ = relay.udp.WriteToUDPAddrPort(response, client)
			}
		}
	}
}

func (relay *dnsRelay) exchangeUDP(ctx context.Context, query []byte) ([]byte, error) {
	var errs []error
	for _, upstream := range relay.upstreams {
		dialer := net.Dialer{Timeout: dnsExchangeTimeout}
		connection, err := dialer.DialContext(ctx, "udp4", upstream.String())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		_ = connection.SetDeadline(time.Now().Add(dnsExchangeTimeout))
		if _, err = connection.Write(query); err == nil {
			response := make([]byte, dnsMaxMessage)
			var count int
			count, err = connection.Read(response)
			if err == nil {
				_ = connection.Close()
				return append([]byte(nil), response[:count]...), nil
			}
		}
		_ = connection.Close()
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (relay *dnsRelay) serveTCP(ctx context.Context) error {
	for {
		client, err := relay.tcp.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept downstream TCP DNS: %w", err)
		}
		relay.trackClient(client, true)
		relay.handlers.Add(1)
		go func() {
			defer relay.handlers.Done()
			defer relay.trackClient(client, false)
			defer client.Close()
			relay.handleTCPClient(ctx, client)
		}()
	}
}

func (relay *dnsRelay) handleTCPClient(ctx context.Context, client net.Conn) {
	length := make([]byte, 2)
	for {
		_ = client.SetDeadline(time.Now().Add(dnsExchangeTimeout))
		if _, err := io.ReadFull(client, length); err != nil {
			return
		}
		messageLength := int(binary.BigEndian.Uint16(length))
		if messageLength < 12 || messageLength > dnsMaxMessage {
			return
		}
		query := make([]byte, messageLength)
		if _, err := io.ReadFull(client, query); err != nil {
			return
		}
		response, err := relay.exchangeTCP(ctx, query)
		if err != nil {
			response = dnsServerFailure(query)
		}
		if len(response) == 0 || len(response) > dnsMaxMessage {
			return
		}
		binary.BigEndian.PutUint16(length, uint16(len(response)))
		if _, err := client.Write(length); err != nil {
			return
		}
		if _, err := client.Write(response); err != nil {
			return
		}
	}
}

func (relay *dnsRelay) exchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	var errs []error
	for _, upstream := range relay.upstreams {
		dialer := net.Dialer{Timeout: dnsExchangeTimeout}
		connection, err := dialer.DialContext(ctx, "tcp4", upstream.String())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		_ = connection.SetDeadline(time.Now().Add(dnsExchangeTimeout))
		length := []byte{byte(len(query) >> 8), byte(len(query))}
		if _, err = connection.Write(length); err == nil {
			_, err = connection.Write(query)
		}
		if err == nil {
			_, err = io.ReadFull(connection, length)
		}
		var response []byte
		if err == nil {
			messageLength := int(binary.BigEndian.Uint16(length))
			if messageLength < 12 || messageLength > dnsMaxMessage {
				err = fmt.Errorf("upstream TCP DNS returned invalid message length %d", messageLength)
			} else {
				response = make([]byte, messageLength)
				_, err = io.ReadFull(connection, response)
			}
		}
		_ = connection.Close()
		if err == nil {
			return response, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (relay *dnsRelay) trackClient(client net.Conn, add bool) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if add {
		relay.clients[client] = true
	} else {
		delete(relay.clients, client)
	}
}

func dnsServerFailure(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	response := append([]byte(nil), query...)
	response[2] |= 0x80 // QR: response
	response[3] = response[3]&0xf0 | 0x02
	for index := 6; index < 12; index++ {
		response[index] = 0
	}
	return response
}

// ProbeDNSResolver performs one bounded root NS query against a classic IPv4
// port-53 resolver. It is used only by the read-only doctor workflow.
func ProbeDNSResolver(ctx context.Context, address netip.Addr) error {
	if !usableDNSAddress(address) {
		return fmt.Errorf("DNS resolver address is not usable IPv4")
	}
	return probeDNSResolver(ctx, netip.AddrPortFrom(address, dnsPort))
}

func probeDNSResolver(ctx context.Context, resolver netip.AddrPort) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := net.Dialer{Timeout: dnsExchangeTimeout}
	connection, err := dialer.DialContext(ctx, "udp4", resolver.String())
	if err != nil {
		return fmt.Errorf("connect to DNS resolver %s: %w", resolver.Addr(), err)
	}
	defer connection.Close()
	deadline := time.Now().Add(dnsExchangeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	query := []byte{
		0x67, 0x6c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	}
	if _, err := connection.Write(query); err != nil {
		return fmt.Errorf("query DNS resolver %s: %w", resolver.Addr(), err)
	}
	response := make([]byte, dnsMaxMessage)
	count, err := connection.Read(response)
	if err != nil {
		return fmt.Errorf("read DNS resolver %s: %w", resolver.Addr(), err)
	}
	if count < 12 || response[0] != query[0] || response[1] != query[1] || response[2]&0x80 == 0 {
		return fmt.Errorf("DNS resolver %s returned an invalid response", resolver.Addr())
	}
	return nil
}
