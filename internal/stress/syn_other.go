//go:build !linux

package stress

import "fmt"

// synRun is unavailable off Linux because it relies on raw sockets.
func synRun(target string, port, threads, duration int) error {
	return fmt.Errorf("stress syn uses raw sockets and is only supported on Linux")
}
