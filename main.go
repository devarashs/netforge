// netforge is a single-binary network and security toolkit: load/resilience
// testing, X.509 certificate generation, everyday cryptography, and read-only
// network diagnostics.
//
// The stress-testing commands are for infrastructure you own or are explicitly
// authorized to test. They require the -i-am-authorized flag and use your real
// source address — no spoofing.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/devarashs/netforge/internal/certtool"
	"github.com/devarashs/netforge/internal/cli"
	"github.com/devarashs/netforge/internal/cryptotool"
	"github.com/devarashs/netforge/internal/nettool"
	"github.com/devarashs/netforge/internal/stress"
)

func main() {
	root := &cli.Command{
		Name:  "netforge",
		Short: "network & security toolkit",
		Long:  "netforge — stress testing, certificates, cryptography, and network diagnostics.",
		Sub: []*cli.Command{
			stress.Command(),
			certtool.Command(),
			cryptotool.Command(),
			nettool.Command(),
		},
	}

	if err := root.Execute(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return // -h already printed usage
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
