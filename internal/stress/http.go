package stress

import (
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/devarashs/netforge/internal/cli"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
	"Mozilla/5.0 (X11; Linux x86_64)",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
	"Mozilla/5.0 (Android 11; Mobile; rv:89.0)",
}

func parseHeaders(list string) map[string]string {
	h := make(map[string]string)
	for _, pair := range strings.Split(list, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if kv := strings.SplitN(pair, ":", 2); len(kv) == 2 {
			h[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return h
}

func httpCmd() *cli.Command {
	return &cli.Command{
		Name:  "http",
		Short: "HTTP request-rate stress test",
		Run: func(args []string) error {
			fs := newFlagSet("stress http")
			url := fs.String("url", "", "target URL, e.g. http://127.0.0.1:8080/ (required)")
			method := fs.String("method", "GET", "HTTP method")
			threads := fs.Int("threads", 50, "concurrent workers")
			duration := fs.Int("duration", 30, "duration in seconds")
			data := fs.String("data", "", "request body (for POST/PUT)")
			headerList := fs.String("headers", "", "custom headers, format Key1:Val1;Key2:Val2")
			timeout := fs.Int("timeout", 5, "per-request timeout in seconds")
			authorized := fs.Bool("i-am-authorized", false, "confirm you are authorized to test the target")
			if err := fs.Parse(args); err != nil {
				return err
			}
			if *url == "" || !strings.HasPrefix(*url, "http") {
				fs.Usage()
				return errRequired("-url must be an http(s) URL")
			}
			if err := authGate(*authorized, *url); err != nil {
				return err
			}

			headers := parseHeaders(*headerList)
			m := strings.ToUpper(*method)
			runWorkers("http", "requests", *threads, *duration,
				func(stop <-chan struct{}, deadline time.Time, st *stats) {
					client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
					for {
						select {
						case <-stop:
							return
						default:
						}
						if time.Now().After(deadline) {
							return
						}
						var body io.Reader
						if *data != "" {
							body = strings.NewReader(*data)
						}
						req, err := http.NewRequest(m, *url, body)
						if err != nil {
							return
						}
						req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
						req.Header.Set("Accept", "*/*")
						req.Header.Set("Connection", "close")
						for k, v := range headers {
							req.Header.Set(k, v)
						}
						resp, err := client.Do(req)
						if err == nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
							st.inc()
						}
					}
				})
			return nil
		},
	}
}
