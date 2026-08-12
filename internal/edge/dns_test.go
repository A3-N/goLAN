package edge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDNSRelayProxiesLoopbackUDPAndTCP(t *testing.T) {
	upstreamUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamUDP.Close()
	upstreamAddress := upstreamUDP.LocalAddr().(*net.UDPAddr).AddrPort()
	upstreamTCP, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(upstreamAddress))
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamTCP.Close()

	go serveTestUDP(t, upstreamUDP)
	go serveTestTCP(t, upstreamTCP)

	relay, err := listenDNSRelay(
		netip.MustParseAddrPort("127.0.0.1:0"),
		[]netip.AddrPort{upstreamAddress},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relay.Run(ctx) }()
	relayAddress := relay.udp.LocalAddr().(*net.UDPAddr).AddrPort()
	query := testDNSQuery()

	udpClient, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(relayAddress))
	if err != nil {
		t.Fatal(err)
	}
	_ = udpClient.SetDeadline(time.Now().Add(time.Second))
	if _, err := udpClient.Write(query); err != nil {
		t.Fatal(err)
	}
	udpResponse := make([]byte, 512)
	count, err := udpClient.Read(udpResponse)
	_ = udpClient.Close()
	if err != nil || count != len(query) || udpResponse[2]&0x80 == 0 {
		t.Fatalf("UDP response count=%d flags=%x error=%v", count, udpResponse[:min(count, 4)], err)
	}

	tcpClient, err := net.DialTimeout("tcp4", relayAddress.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = tcpClient.SetDeadline(time.Now().Add(time.Second))
	length := []byte{0, byte(len(query))}
	if _, err := tcpClient.Write(append(length, query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tcpClient, length); err != nil {
		t.Fatal(err)
	}
	tcpResponse := make([]byte, binary.BigEndian.Uint16(length))
	if _, err := io.ReadFull(tcpClient, tcpResponse); err != nil {
		t.Fatal(err)
	}
	_ = tcpClient.Close()
	if len(tcpResponse) != len(query) || tcpResponse[2]&0x80 == 0 {
		t.Fatalf("TCP response flags=%x", tcpResponse[:min(len(tcpResponse), 4)])
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS relay did not stop after cancellation")
	}
}

func serveTestUDP(t *testing.T, server *net.UDPConn) {
	t.Helper()
	buffer := make([]byte, 512)
	count, client, err := server.ReadFromUDP(buffer)
	if err != nil {
		return
	}
	response := append([]byte(nil), buffer[:count]...)
	response[2] |= 0x80
	_, _ = server.WriteToUDP(response, client)
}

func serveTestTCP(t *testing.T, server *net.TCPListener) {
	t.Helper()
	client, err := server.AcceptTCP()
	if err != nil {
		return
	}
	defer client.Close()
	length := make([]byte, 2)
	if _, err := io.ReadFull(client, length); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(length))
	if _, err := io.ReadFull(client, query); err != nil {
		return
	}
	query[2] |= 0x80
	_, _ = client.Write(length)
	_, _ = client.Write(query)
}

func testDNSQuery() []byte {
	// Header plus one A question for "a".
	return []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 'a', 0x00, 0x00,
		0x01, 0x00, 0x01,
	}
}

func TestRelayLeaseDNSDoesNotAdvertiseLoopback(t *testing.T) {
	lease, err := LeaseForSubnet(
		netip.MustParsePrefix("10.77.4.0/24"),
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease = relayLeaseDNS(lease, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if len(lease.DNS) != 1 || lease.DNS[0] != lease.ServerIP {
		t.Fatalf("advertised DNS=%v server=%s", lease.DNS, lease.ServerIP)
	}
}

func TestProbeDNSResolverRequiresAValidResponse(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go serveTestUDP(t, server)
	address := server.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := probeDNSResolver(context.Background(), address); err != nil {
		t.Fatal(err)
	}
}
