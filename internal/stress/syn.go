package stress

import (
	"github.com/devarashs/netforge/internal/cli"
)

// synCmd parses flags; the actual raw-socket work is in synRun, which is
// implemented per-OS (raw sockets are Linux-only here).
func synCmd() *cli.Command {
	return &cli.Command{
		Name:  "syn",
		Short: "TCP SYN stress test (Linux, requires root)",
		Run: func(args []string) error {
			fs := newFlagSet("stress syn")
			target := fs.String("target", "", "target IPv4 address (required)")
			port := fs.Int("port", 80, "target port")
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
			return synRun(*target, *port, *threads, *duration)
		},
	}
}
