// Package nettool provides read-only network diagnostics: TCP port scanning,
// TCP latency probing, uptime monitoring, DNS lookups and local interface
// listing. Nothing here generates attack traffic.
package nettool

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/devarashs/netforge/internal/cli"
)

// Command returns the "net" command group.
func Command() *cli.Command {
	return &cli.Command{
		Name:  "net",
		Short: "network diagnostics: scan, ping, monitor, dns, ifaces",
		Sub: []*cli.Command{
			scanCmd(),
			pingCmd(),
			monitorCmd(),
			dnsCmd(),
			ifacesCmd(),
		},
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parsePorts expands a spec like "22,80,443,8000-8100" into a sorted slice.
func parsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err := strconv.Atoi(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("bad port range %q", part)
			}
			b, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("bad port range %q", part)
			}
			if a > b {
				a, b = b, a
			}
			for p := a; p <= b; p++ {
				seen[p] = true
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		seen[p] = true
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range", p)
		}
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func scanCmd() *cli.Command {
	return &cli.Command{
		Name:  "scan",
		Short: "TCP connect port scan",
		Run: func(args []string) error {
			fs := newFlagSet("net scan")
			host := fs.String("host", "", "target host or IP (required)")
			portsSpec := fs.String("ports", "1-1024", "ports, e.g. 22,80,443,8000-8100")
			timeout := fs.Int("timeout", 800, "per-port timeout in milliseconds")
			concurrency := fs.Int("concurrency", 200, "max simultaneous probes")
			if err := fs.Parse(args); err != nil {
				return err
			}
			if *host == "" {
				fs.Usage()
				return fmt.Errorf("-host is required")
			}
			ports, err := parsePorts(*portsSpec)
			if err != nil {
				return err
			}

			fmt.Printf("scanning %s (%d ports)\n", *host, len(ports))
			sem := make(chan struct{}, *concurrency)
			var wg sync.WaitGroup
			var mu sync.Mutex
			var open []int
			to := time.Duration(*timeout) * time.Millisecond
			for _, p := range ports {
				wg.Add(1)
				sem <- struct{}{}
				go func(port int) {
					defer wg.Done()
					defer func() { <-sem }()
					addr := net.JoinHostPort(*host, strconv.Itoa(port))
					conn, err := net.DialTimeout("tcp", addr, to)
					if err != nil {
						return
					}
					conn.Close()
					mu.Lock()
					open = append(open, port)
					mu.Unlock()
				}(p)
			}
			wg.Wait()
			sort.Ints(open)
			if len(open) == 0 {
				fmt.Println("no open ports found")
				return nil
			}
			for _, p := range open {
				name := knownService(p)
				fmt.Printf("  %5d/tcp open  %s\n", p, name)
			}
			return nil
		},
	}
}

func pingCmd() *cli.Command {
	return &cli.Command{
		Name:  "ping",
		Short: "measure TCP connect latency to host:port",
		Run: func(args []string) error {
			fs := newFlagSet("net ping")
			host := fs.String("host", "", "target host or IP (required)")
			port := fs.Int("port", 443, "target port")
			count := fs.Int("count", 5, "number of probes")
			interval := fs.Int("interval", 1000, "delay between probes in milliseconds")
			timeout := fs.Int("timeout", 2000, "per-probe timeout in milliseconds")
			if err := fs.Parse(args); err != nil {
				return err
			}
			if *host == "" {
				fs.Usage()
				return fmt.Errorf("-host is required")
			}
			addr := net.JoinHostPort(*host, strconv.Itoa(*port))
			to := time.Duration(*timeout) * time.Millisecond
			var rtts []time.Duration
			var failures int
			for i := 0; i < *count; i++ {
				start := time.Now()
				conn, err := net.DialTimeout("tcp", addr, to)
				elapsed := time.Since(start)
				if err != nil {
					failures++
					fmt.Printf("probe %d: failed (%v)\n", i+1, err)
				} else {
					conn.Close()
					rtts = append(rtts, elapsed)
					fmt.Printf("probe %d: %s in %.2f ms\n", i+1, addr, float64(elapsed.Microseconds())/1000)
				}
				if i < *count-1 {
					time.Sleep(time.Duration(*interval) * time.Millisecond)
				}
			}
			summarize(rtts, failures, *count)
			return nil
		},
	}
}

func summarize(rtts []time.Duration, failures, total int) {
	fmt.Printf("\n%d/%d succeeded", total-failures, total)
	if len(rtts) == 0 {
		fmt.Println()
		return
	}
	min, max, sum := rtts[0], rtts[0], time.Duration(0)
	for _, r := range rtts {
		if r < min {
			min = r
		}
		if r > max {
			max = r
		}
		sum += r
	}
	avg := sum / time.Duration(len(rtts))
	fmt.Printf(" | min %.2f ms  avg %.2f ms  max %.2f ms\n",
		ms(min), ms(avg), ms(max))
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func monitorCmd() *cli.Command {
	return &cli.Command{
		Name:  "monitor",
		Short: "continuously monitor host:port targets (Ctrl+C to stop)",
		Run: func(args []string) error {
			fs := newFlagSet("net monitor")
			targets := fs.String("targets", "", "comma-separated host:port list (required)")
			interval := fs.Int("interval", 5, "seconds between rounds")
			timeout := fs.Int("timeout", 2000, "per-check timeout in milliseconds")
			if err := fs.Parse(args); err != nil {
				return err
			}
			if *targets == "" {
				fs.Usage()
				return fmt.Errorf("-targets is required")
			}
			var list []string
			for _, t := range strings.Split(*targets, ",") {
				if t = strings.TrimSpace(t); t != "" {
					list = append(list, t)
				}
			}
			to := time.Duration(*timeout) * time.Millisecond

			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
			fmt.Printf("monitoring %d target(s) every %ds; Ctrl+C to stop\n", len(list), *interval)
			ticker := time.NewTicker(time.Duration(*interval) * time.Second)
			defer ticker.Stop()
			checkAll(list, to)
			for {
				select {
				case <-stop:
					fmt.Println("stopped.")
					return nil
				case <-ticker.C:
					checkAll(list, to)
				}
			}
		},
	}
}

func checkAll(targets []string, to time.Duration) {
	stamp := time.Now().Format("15:04:05")
	for _, t := range targets {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", t, to)
		if err != nil {
			fmt.Printf("[%s] %-25s DOWN (%v)\n", stamp, t, err)
			continue
		}
		conn.Close()
		fmt.Printf("[%s] %-25s UP   %.2f ms\n", stamp, t, ms(time.Since(start)))
	}
}

func dnsCmd() *cli.Command {
	return &cli.Command{
		Name:  "dns",
		Short: "DNS lookups (a, aaaa, mx, txt, ns, cname)",
		Run: func(args []string) error {
			fs := newFlagSet("net dns")
			name := fs.String("name", "", "domain name (required)")
			typ := fs.String("type", "a", "a, aaaa, mx, txt, ns or cname")
			if err := fs.Parse(args); err != nil {
				return err
			}
			if *name == "" {
				fs.Usage()
				return fmt.Errorf("-name is required")
			}
			switch strings.ToLower(*typ) {
			case "a", "aaaa":
				ips, err := net.LookupIP(*name)
				if err != nil {
					return err
				}
				want4 := strings.ToLower(*typ) == "a"
				for _, ip := range ips {
					is4 := ip.To4() != nil
					if is4 == want4 {
						fmt.Println(ip)
					}
				}
			case "mx":
				mxs, err := net.LookupMX(*name)
				if err != nil {
					return err
				}
				for _, mx := range mxs {
					fmt.Printf("%d  %s\n", mx.Pref, mx.Host)
				}
			case "txt":
				txts, err := net.LookupTXT(*name)
				if err != nil {
					return err
				}
				for _, t := range txts {
					fmt.Println(t)
				}
			case "ns":
				nss, err := net.LookupNS(*name)
				if err != nil {
					return err
				}
				for _, ns := range nss {
					fmt.Println(ns.Host)
				}
			case "cname":
				cname, err := net.LookupCNAME(*name)
				if err != nil {
					return err
				}
				fmt.Println(cname)
			default:
				return fmt.Errorf("unknown record type %q", *typ)
			}
			return nil
		},
	}
}

func ifacesCmd() *cli.Command {
	return &cli.Command{
		Name:  "ifaces",
		Short: "list local network interfaces and addresses",
		Run: func(args []string) error {
			fs := newFlagSet("net ifaces")
			if err := fs.Parse(args); err != nil {
				return err
			}
			ifaces, err := net.Interfaces()
			if err != nil {
				return err
			}
			for _, ifc := range ifaces {
				addrs, _ := ifc.Addrs()
				if len(addrs) == 0 {
					continue
				}
				fmt.Printf("%s (mtu %d) %s\n", ifc.Name, ifc.MTU, ifc.Flags)
				for _, a := range addrs {
					fmt.Printf("    %s\n", a.String())
				}
			}
			return nil
		},
	}
}

func knownService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 6379:
		return "redis"
	case 8080:
		return "http-alt"
	case 27017:
		return "mongodb"
	default:
		return ""
	}
}
