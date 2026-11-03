// Copyright 2026 The Apassy authors
// SPDX-License-Identifier: Apache-2.0

// Apassy additions to the vendored libtailscale package (see VENDORED.md).
// The vendored files stay byte-identical to the pinned upstream commit. This
// file is the only Go code that Apassy writes. It uses only packages that
// tsnet already imports, so go.mod and go.sum stay the upstream files.

package main

//#include <errno.h>
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/logtail"
)

// tsnet uploads its debug logs to log.tailscale.com by default (tsnet.go,
// startLogger). Apassy turns the upload off for the life of the process, as
// tailscaled's --no-logs-no-support does. The logs still go to the log fd of
// tailscale_set_logfd and to the buffer files in the state directory.
//
// This must not call envknob.SetNoLogsNoSupport: that calls setenv, and the Go
// runtime of a c-archive initializes on its own thread while the Rust main
// thread can read the environment.
func init() {
	logtail.Disable()
}

// ApassyTailnetWhoisJSON writes the JSON of the LocalAPI WhoIs answer
// (apitype.WhoIsResponse) for addr, an IP address or an IP address with a port,
// to *jsonOut as a NUL-terminated, malloc'd string. The caller frees it with
// free(). Like TsnetStatusJSON, it uses the in-memory LocalAPI of tsnet, so it
// needs no loopback TCP listener.
//
// Returns:
//
//	0      - success, *jsonOut is set
//	EBADF  - sd is not a valid tailscale
//	ENOENT - no node of the tailnet has this address
//	-1     - call tailscale_errmsg for details (*jsonOut is NULL)
//
//export ApassyTailnetWhoisJSON
func ApassyTailnetWhoisJSON(sd C.int, addr *C.char, jsonOut **C.char) C.int {
	if jsonOut == nil {
		panic("whois_json passed nil json_out")
	}
	*jsonOut = nil
	if addr == nil {
		panic("whois_json passed nil addr")
	}
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	who, err := lc.WhoIs(ctx, C.GoString(addr))
	if errors.Is(err, local.ErrPeerNotFound) {
		s.recErr(err)
		return C.ENOENT
	}
	if err != nil {
		return s.recErr(err)
	}
	b, err := json.Marshal(who)
	if err != nil {
		return s.recErr(err)
	}
	*jsonOut = C.CString(string(b))
	return 0
}
