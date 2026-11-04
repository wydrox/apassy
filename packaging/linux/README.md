# Apassy node for Linux

The Apassy node without a window: the relay of the questions, the feed, the access
requests, and relay sync of your devices, and a team host for `apassy team`. Your Mac
and your iPhone reach it over Tailscale, at `https://<Tailscale IPv4>:8444`, behind a
self-signed certificate that they pin. Nothing listens on `0.0.0.0` or `::`.

## Install

- `.deb` (Debian 11 or later, Ubuntu 20.04 or later): `sudo apt install ./apassy_<version>_<arch>.deb`.
  It installs `/usr/bin/apassy`, the `apassy-team` shim, and the user unit template.
- Tarball: put `apassy` and `apassy-team` in a directory on your `PATH`, for example
  `~/.local/bin`.
- Or: `curl -fsSL https://apassy-relay.wyderka.cc/install.sh | sh`, which checks the
  SHA-256 of the tarball and installs into `~/.local/bin`.

Check the download against `SHA256SUMS` (`sha256sum -c --ignore-missing SHA256SUMS`) and
its GitHub attestation (`gh attestation verify <file> --repo wydrox/apassy`).

## Start

1. Install Tailscale and sign in: `sudo tailscale up`.
2. As your own user (not root): `apassy up`. It writes and starts the systemd user
   service `apassy-node.service` and prints a pairing link and QR code.
3. Once, to start the node at boot without a login: `sudo loginctl enable-linger $USER`.
4. In Apassy on the Mac: "Your own node", then scan the QR code.

`apassy status`, `apassy doctor`, `apassy pair`, and `apassy uninstall` do the rest.
`apassy-team` is `apassy team` for one more release.

The guide: https://github.com/wydrox/apassy/blob/main/docs/operations/linux-node.md
