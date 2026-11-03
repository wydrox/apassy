// Spike only (Apassy plan s8 unit T0, ADR 0040). Not a part of libtailscale.
//
// scripts/build-spike-libs.sh copies this file into the pinned libtailscale checkout (package
// main) before it builds the c-archive, so these functions run in the same Go runtime as tsnet.
// Their C declarations are in Native/include/tailnet_spike_go.h.

package main

//#include <stdlib.h>
import "C"

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/logtail"
)

// ApassySpikeNoLogs turns on TS_NO_LOGS_NO_SUPPORT inside Go (the log transport then sends
// nothing) and calls logtail.Disable (log entries are then neither buffered nor uploaded). Call
// it before tailscale_start. It returns 1 when Go then reports the no-logs mode.
//
//export ApassySpikeNoLogs
func ApassySpikeNoLogs() C.int {
	envknob.SetNoLogsNoSupport()
	logtail.Disable()
	if envknob.NoLogsNoSupport() {
		return 1
	}
	return 0
}

// ApassySpikeGetenv returns the value of an environment variable as Go sees it, or NULL when
// it is not set. The caller frees the string. The spike asks it after a setenv in Swift: the Go
// runtime of a c-archive may copy the environment once, when the library loads.
//
//export ApassySpikeGetenv
func ApassySpikeGetenv(name *C.char) *C.char {
	value, ok := os.LookupEnv(C.GoString(name))
	if !ok {
		return nil
	}
	return C.CString(value)
}

// ApassySpikeSetTraceback sets GOTRACEBACK. With "crash", a Go panic ends in abort() (SIGABRT,
// so iOS writes a crash report); by default it ends with exit(2) and no report.
//
//export ApassySpikeSetTraceback
func ApassySpikeSetTraceback(level *C.char) {
	debug.SetTraceback(C.GoString(level))
}

// ApassySpikeGoCrash ends the process from Go. 0: a panic on the calling (C) thread. 1: a panic
// in a new goroutine, as a bug inside tsnet would be. 2: a nil dereference, a SIGSEGV that the
// Go runtime turns into a panic.
//
//export ApassySpikeGoCrash
func ApassySpikeGoCrash(kind C.int) {
	switch kind {
	case 0:
		panic("apassy spike: a Go panic on the calling thread")
	case 1:
		go func() {
			panic("apassy spike: a Go panic in a goroutine")
		}()
		time.Sleep(10 * time.Second)
	default:
		var p *int
		*p = 1
	}
}

// ApassySpikeGoInfo returns JSON with the Go version and the state of the Go runtime. The
// caller frees the string.
//
//export ApassySpikeGoInfo
func ApassySpikeGoInfo() *C.char {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	info := map[string]any{
		"go_version":        runtime.Version(),
		"goos":              runtime.GOOS,
		"goarch":            runtime.GOARCH,
		"goroutines":        runtime.NumGoroutine(),
		"gomaxprocs":        runtime.GOMAXPROCS(0),
		"sys_bytes":         m.Sys,
		"heap_inuse_bytes":  m.HeapInuse,
		"stack_inuse_bytes": m.StackInuse,
		"num_gc":            m.NumGC,
		"no_logs":           envknob.NoLogsNoSupport(),
	}
	b, err := json.Marshal(info)
	if err != nil {
		return C.CString("{}")
	}
	return C.CString(string(b))
}
