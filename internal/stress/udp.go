package stress

import (
	"math/rand"
	"net"
	"time"

	"github.com/devarashs/netforge/internal/cli"
)

func udpCmd() *cli.Command {
	return &cli.Command{
		Name:  "udp",
		Short: "UDP packet stress test",
		Run: func(args []string) error {
			fs := newFlagSet("stress udp")
			target := fs.String("target", "", "target host or IP (required)")
			port := fs.String("port", "80", "target port")
			threads := fs.Int("threads", 50, "concurrent workers")
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

			udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(*target, *port))
			if err != nil {
				return err
			}
			runWorkers("udp", "packets", *threads, *duration,
				func(stop <-chan struct{}, deadline time.Time, st *stats) {
					conn, err := net.DialUDP("udp", nil, udpAddr)
					if err != nil {
						return
					}
					defer conn.Close()
					for {
						select {
						case <-stop:
							return
						default:
						}
						if time.Now().After(deadline) {
							return
						}
						payload := randomBytes(1024 + rand.Intn(1024))
						conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
						if _, err := conn.Write(payload); err == nil {
							st.inc()
						}
					}
				})
			return nil
		},
	}
}
