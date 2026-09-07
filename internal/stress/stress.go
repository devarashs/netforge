// Package stress contains load-generation tools for testing the resilience of
// infrastructure you own or are explicitly authorized to test.
//
// Every command in this package refuses to run unless the operator passes the
// -i-am-authorized flag. None of these tools spoof their source address: the
// traffic they generate comes from the real host running them, which is what
// you want when load-testing your own systems and is the honest default.
package stress

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/devarashs/netforge/internal/cli"
)

// stats is a lock-free counter shared across workers.
type stats struct{ n uint64 }

func (s *stats) inc()        { atomic.AddUint64(&s.n, 1) }
func (s *stats) get() uint64 { return atomic.LoadUint64(&s.n) }

// worker runs load until stop is closed or the deadline passes.
type worker func(stop <-chan struct{}, deadline time.Time, st *stats)

// Command returns the "stress" command group.
func Command() *cli.Command {
	return &cli.Command{
		Name:  "stress",
		Short: "load / resilience testing (authorized targets only)",
		Long:  "Generate load against systems you own or are authorized to test. All\ncommands require -i-am-authorized and use your real source address.",
		Sub: []*cli.Command{
			httpCmd(),
			tcpCmd(),
			udpCmd(),
			icmpCmd(),
			synCmd(),
		},
	}
}

// errRequired reports a missing or invalid required flag.
func errRequired(msg string) error { return fmt.Errorf("%s", msg) }

// authGate returns an error unless the operator confirmed authorization.
func authGate(authorized bool, target string) error {
	if authorized {
		return nil
	}
	return fmt.Errorf(
		"refusing to run against %q: pass -i-am-authorized to confirm you own\n"+
			"      or have explicit written permission to test this target",
		target)
}

// runWorkers spawns n copies of fn, prints periodic progress, handles Ctrl+C,
// and blocks until every worker returns. It reports the final counter.
func runWorkers(label, unit string, n, seconds int, fn worker) uint64 {
	st := &stats{}
	stop := make(chan struct{})
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	var once sync.Once
	go func() {
		<-sig
		once.Do(func() { close(stop) })
	}()

	fmt.Printf("[%s] starting %d workers for %ds\n", label, n, seconds)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(stop, deadline, st)
		}()
	}

	done := make(chan struct{})
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				fmt.Printf("[%s] %s so far: %d\n", label, unit, st.get())
			}
		}
	}()

	wg.Wait()
	close(done)
	signal.Stop(sig)
	total := st.get()
	fmt.Printf("[%s] finished. total %s: %d\n", label, unit, total)
	return total
}

// newFlagSet builds a flag set that reports errors to stderr and returns
// flag.ErrHelp on -h without exiting the process.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
