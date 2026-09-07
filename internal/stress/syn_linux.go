//go:build linux

package stress

import (
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"
)

// buildSynPacket assembles a bare IPv4 + TCP SYN segment.
//
// The source address is the real outbound address of this host — this tool
// does not spoof. Spoofing adds nothing to a legitimate load test (you want to
// see the traffic's true origin) and is dropped by any network doing egress
// filtering, so the honest source is both safer and more useful.
func buildSynPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	ip[3] = 0x34 // total length: 52 bytes (20 IP + 20 TCP + 12 options)
	ip[6] = 0x40 // don't fragment
	ip[8] = 64   // TTL
	ip[9] = 6    // protocol: TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	cs := checksum(ip)
	ip[10] = byte(cs >> 8)
	ip[11] = byte(cs & 0xff)

	tcp := make([]byte, 20)
	tcp[0] = byte(srcPort >> 8)
	tcp[1] = byte(srcPort & 0xff)
	tcp[2] = byte(dstPort >> 8)
	tcp[3] = byte(dstPort & 0xff)
	seq := rand.Uint32()
	tcp[4] = byte(seq >> 24)
	tcp[5] = byte(seq >> 16)
	tcp[6] = byte(seq >> 8)
	tcp[7] = byte(seq)
	tcp[12] = 0x50 // data offset: 5 words
	tcp[13] = 0x02 // flags: SYN
	tcp[14] = 0x71 // window
	tcp[15] = 0x10

	// TCP checksum over the pseudo-header + segment.
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6 // protocol
	pseudo[10] = byte(len(tcp) >> 8)
	pseudo[11] = byte(len(tcp) & 0xff)
	copy(pseudo[12:], tcp)
	tcs := checksum(pseudo)
	tcp[16] = byte(tcs >> 8)
	tcp[17] = byte(tcs & 0xff)

	return append(ip, tcp...)
}

// localIPFor discovers the outbound source address for reaching dst without
// sending any traffic (a UDP "connect" only fixes the route).
func localIPFor(dst net.IP) (net.IP, error) {
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "80"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.To4(), nil
	}
	return nil, fmt.Errorf("could not determine local source address")
}

func synRun(target string, port, threads, duration int) error {
	dstIP := net.ParseIP(target).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid IPv4 target %q", target)
	}
	srcIP, err := localIPFor(dstIP)
	if err != nil {
		return fmt.Errorf("resolve local source address: %w", err)
	}
	dstPort := uint16(port)

	runWorkers("syn", "packets", threads, duration,
		func(stop <-chan struct{}, deadline time.Time, st *stats) {
			sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
			if err != nil {
				return // needs root
			}
			defer syscall.Close(sock)
			sa := &syscall.SockaddrInet4{Port: int(dstPort)}
			copy(sa.Addr[:], dstIP)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if time.Now().After(deadline) {
					return
				}
				srcPort := uint16(rand.Intn(65535-1024) + 1024)
				pkt := buildSynPacket(srcIP, dstIP, srcPort, dstPort)
				if err := syscall.Sendto(sock, pkt, 0, sa); err == nil {
					st.inc()
				}
			}
		})
	return nil
}
