# Vendored libtailscale

The Go package in this directory is [libtailscale](https://github.com/tailscale/libtailscale)
at commit `ac7ed43af14e19e1c1810ee9f8319872c6beb412` (2026-10-30), with one Apassy file added.
`go build -buildmode=c-archive` in this directory makes `libtailscale.a`: the Go runtime,
`tailscale.com/tsnet` v1.104.1, and the C functions of `tailscale.h`. `build.rs` of the crate
runs that command (see `../pins.env` for the pinned Go version).

License: BSD-3-Clause, `LICENSE` here (a copy is in `licenses/libtailscale/`). The modules
that the archive links are listed in `go.sum`. Their licenses are in
`licenses/THIRD-PARTY-NOTICES.md`, section "Embedded tailnet node".

## Files

Copied byte for byte from the commit. SHA-256 of each file:

| File | SHA-256 |
| --- | --- |
| `LICENSE` | `d6e14a92f27cd6c82f8914041c1bb43819fcf3167b827b9198c2c803d4dff5d3` |
| `go.mod` | `71b27d3e43394c4722730e1e08a23afff48a691eb1ebec5552dcb7c60bff13d9` |
| `go.sum` | `5bd4b5552ddc90f28560bcf155b9384683bfe2df2c60667d831a612794ebc85a` |
| `tailscale.go` | `5e010d30874f06721139e533813feecee9e3989c5343e2c472f52a20daac2672` |
| `tailscale.c` | `0d10f2f199cd8484e9c6b5b30f17004f1497b08a9121edf86a87a0b83d38c281` |
| `tailscale.h` | `36e87d165bbd3bdca5fa9b21a861c793ce052b7539f271c0b8c802e8b66e937a` |
| `fd_linux.go` | `569a1fd02fc23ea0fa4d6a200b367e16d96f2d2b8240f3520feed04df140cac2` |
| `fd_other.go` | `0ad0676bec37ec1765f91d16c254aaad65b190a0703ba2938cae6553284cea0a` |

Not copied: the tests (`tailscale_test.go`, `tsnetctest/`, `tstestcontrol/`), the
bindings (`swift/`, `python/`, `ruby/`), `sourcepkg/`, `example/`, and the `Makefile`.

Added by Apassy (Apache-2.0): `apassy.go`. It turns off the log upload of tsnet
(`logtail.Disable`) and exports `ApassyTailnetWhoisJSON`, the LocalAPI WhoIs over the
in-memory LocalAPI, like the upstream `tailscale_status_json`. It imports only packages
that tsnet already uses, so `go.mod` and `go.sum` stay the upstream files.

## Update to a new commit

1. Clone libtailscale into a new, empty directory and check out the new commit.
2. Copy the files of the table into this directory. Do not change them.
3. Update the table, `LIBTAILSCALE_COMMIT` and `TAILSCALE_VERSION` in `../pins.env`, and
   `GO_VERSION` with its checksums if the new `go.mod` needs a newer Go.
4. Read the diff of `tailscale.h` and `tailscale.go`: `src/ffi.rs` declares each C
   function by hand, and the ownership rules of each file descriptor are written there.
5. Run the manual workflow `tailnet-spike.yml` and compare the numbers with
   `docs/design/spike-tsnet.md`.

Check the hashes with `shasum -a 256 LICENSE go.mod go.sum tailscale.go tailscale.c tailscale.h fd_linux.go fd_other.go`.
