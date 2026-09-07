package stress

import (
	crand "crypto/rand"
	"math/rand"
	"net"
	"time"

	"github.com/devarashs/netforge/internal/cli"
)

func randomBytes(size int) []byte {
	b := make([]byte, size)
	_, _ = crand.Read(b)
	return b
}

func tcpCmd() *cli.Command {
	return &cli.Command{
		Name:  "tcp",
		Short: "TCP connection + payload stress test",
		Run: func(args []string) error {
			fs := newFlagSet("stress tcp")
			target := fs.String("target", "", "target host or IP (required)")
			port := fs.String("port", "80", "target port")
			threads := fs.Int("threads", 50, "concurrent workers")
			duration := fs.Int("duration", 30, "duration in seconds")
			conns := fs.Int("conns", 20, "connections opened per worker loop")
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

			addr := net.JoinHostPort(*target, *port)
			runWorkers("tcp", "writes", *threads, *duration,
				func(stop <-chan struct{}, deadline time.Time, st *stats) {
					for {
						select {
						case <-stop:
							return
						default:
						}
						if time.Now().After(deadline) {
							return
						}
						for i := 0; i < *conns; i++ {
							conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
							if err != nil {
								continue
							}
							for j := 0; j < 10; j++ {
								payload := randomBytes(4096 + rand.Intn(4096))
								conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
								if _, err := conn.Write(payload); err != nil {
									break
								}
								st.inc()
							}
							conn.Close()
						}
					}
				})
			return nil
		},
	}
}
