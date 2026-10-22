// Package log provides the stderr logging helpers, mirroring src/log.ts.
package log

import (
	"fmt"
	"os"
)

// Log writes an informational message to stderr unless BW_QUIET=true.
func Log(message string) {
	if os.Getenv("BW_QUIET") != "true" {
		fmt.Fprintln(os.Stderr, message)
	}
}

// Verbose writes to stderr only when BWBIO_VERBOSE=true (and not quiet).
func Verbose(message string) {
	if os.Getenv("BWBIO_VERBOSE") == "true" && os.Getenv("BW_QUIET") != "true" {
		fmt.Fprintln(os.Stderr, message)
	}
}

// Debug writes a debug message to stderr when BWBIO_DEBUG=true.
// Debug logs intentionally ignore BW_QUIET because debug mode is explicit.
func Debug(message string) {
	if os.Getenv("BWBIO_DEBUG") == "true" {
		fmt.Fprintln(os.Stderr, "[DEBUG] "+message)
	}
}
