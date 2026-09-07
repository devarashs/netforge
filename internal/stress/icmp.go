package stress

import (
	crand "crypto/rand"
	"net"
	"os"
	"time"

	"github.com/devarashs/netforge/internal/cli"
)

// checksum computes the 16-bit one's-complement checksum used by IP/ICMP/TCP.
func checksum(data []byte) uint16 {
	sum := 0
	for i := 0; i < len(data)-1; i += 2 {
		sum += int(data[i])<<8 | int(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += int(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

func buildICMPEcho(id, seq uint16, payloadSize int) []byte {
	pkt := make([]byte, 8+payloadSize)
	pkt[0] = 8 // type: echo request
	pkt[1] = 0 // code
	pkt[4] = byte(id >> 8)
	pkt[5] = byte(id & 0xff)
	pkt[6] = byte(seq >> 8)
	pkt[7] = byte(seq & 0xff)
	_, _ = crand.Read(pkt[8:])
	cs := checksum(pkt)
	pkt[2] = byte(cs >> 8)
	pkt[3] = byte(cs & 0xff)
	return pkt
}

func icmpCmd() *cli.Command {
	return &cli.Command{
		Name:  "icmp",
		Short: "ICMP echo stress test (requires root)",
		Run: func(args []string) error {
			fs := newFlagSet("stress icmp")
			target := fs.String("target", "", "target IP (required)")
			threads := fs.Int("threads", 20, "concurrent workers")
			duration := fs.Int("duration", 30, "duration in seconds")
			authorized := fs.Bool("i-am-authorized", false, "confirm you are authorized to test the target")
			if err := fs.Parse(args); err != nil {
				return err
			}
			if *target == "" {
				fs.Usage()
				return errRequired("-target is required")
			}
			if err := authGate(*authorized, *target); err != nil {
				return err
			}

			runWorkers("icmp", "packets", *threads, *duration,
				func(stop <-chan struct{}, deadline time.Time, st *stats) {
					conn, err := net.Dial("ip4:icmp", *target)
					if err != nil {
						return // typically "operation not permitted" without root
					}
					defer conn.Close()
					id := uint16(os.Getpid() & 0xffff)
					var seq uint16
					for {
						select {
						case <-stop:
							return
						default:
						}
						if time.Now().After(deadline) {
							return
						}
						conn.SetWriteDeadline(time.Now().Add(time.Second))
						if _, err := conn.Write(buildICMPEcho(id, seq, 56)); err == nil {
							st.inc()
						}
						seq++
					}
				})
			return nil
		},
	}
}
