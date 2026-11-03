// The spike's own Go functions (Native/go/apassy_spike.go), linked into LibTailscale.xcframework
// by scripts/build-spike-libs.sh. Spike only (plan s8 unit T0, ADR 0040).

#ifndef TAILNET_SPIKE_GO_H
#define TAILNET_SPIKE_GO_H

#ifdef __cplusplus
extern "C" {
#endif

// Turns on TS_NO_LOGS_NO_SUPPORT inside Go and calls logtail.Disable(). Call it before
// tailscale_start. Returns 1 when Go then reports the no-logs mode.
extern int ApassySpikeNoLogs(void);

// The value of an environment variable as Go sees it, or NULL when it is not set. free() it.
extern char *ApassySpikeGetenv(const char *name);

// debug.SetTraceback(level). "crash": a Go panic ends in abort(), so iOS writes a crash report.
extern void ApassySpikeSetTraceback(const char *level);

// Ends the process from Go. 0: a panic on the calling thread; 1: a panic in a goroutine;
// 2: a nil dereference (SIGSEGV in Go code).
extern void ApassySpikeGoCrash(int kind);

// JSON: the Go version, goroutines, GOMAXPROCS, and the memory of the Go runtime. free() it.
extern char *ApassySpikeGoInfo(void);

#ifdef __cplusplus
}
#endif

#endif
