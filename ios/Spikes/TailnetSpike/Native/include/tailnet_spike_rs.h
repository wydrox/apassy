// The spike's Rust probe (Native/rust), linked as SpikeRust.xcframework. Spike only (plan s8
// unit T0, ADR 0040).

#ifndef TAILNET_SPIKE_RS_H
#define TAILNET_SPIKE_RS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Takes ownership of fd (a stream from tailscale_dial) and closes it. It sets the read and write
// deadlines on fd, as the vault core will. With use_tls it runs a TLS client (rustls with ring, the
// versions of the vault core) that accepts only a leaf certificate whose SHA-256 equals pin
// (base64url or hex; an empty pin accepts any certificate and only reports it). Then it sends
// "GET path" with the host server_name and reads the answer. Without use_tls, the same request in
// plain text. It writes a JSON report into out (NUL-terminated, cut at out_len) and returns 0 when
// an answer came, -1 otherwise.
int32_t spike_rs_probe(int32_t fd, bool use_tls, const char *server_name, const char *pin,
                       const char *path, uint32_t timeout_ms, char *out, size_t out_len);

// Ends the process from Rust. 0: a panic at the C boundary (Rust aborts); 1: a SIGSEGV (a write
// to an unmapped address); 2: abort().
void spike_rs_crash(int32_t kind);

#ifdef __cplusplus
}
#endif

#endif
