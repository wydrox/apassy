# Third-party notices

Date: 2026-09-26.
Source: `Cargo.lock` at commit `768bbf3`. Review: [storage dependencies](../docs/reviews/storage-dependencies.md).

This file lists the licenses of the storage stack, the TLS stack, and eframe/egui.
The license texts are in the subdirectories of `licenses/`. They are verbatim copies from the crate sources in `~/.cargo/registry/src/`, except `egui/LICENSE-MIT`. That file comes from the egui repository at the crate commit `49682f8b`, because the egui crates do not include a license file.

## Scope and limits

This file does not cover all crates in the build. `Cargo.lock` has 371 packages.
The desktop build also links winit, glutin, glow, accesskit, objc2, image, arboard, and other crates. They are not in this file.
Before the app bundle ships, generate a complete notice for all linked crates. Use the inventory command in [development checks](../docs/operations/checks.md) as a start.

## How the app bundle uses this file

Copy this directory into `Apassy.app/Contents/Resources/Licenses/`.
Show this file, or a link to it, in the About window of the app.
The MIT, ISC, BSD, OFL, and Ubuntu Font licenses need the copyright notice and the license text in the distribution. Apache-2.0 needs a copy of the license.

Where a crate has a choice of licenses ("OR"), Apassy uses the MIT license. The table shows the choice.

## Storage stack

| Component | Version | License used | Text | In the binary |
| --- | --- | --- | --- | --- |
| SQLCipher (Community Edition, Zetetic LLC) | 4.14.0, bundled in libsqlite3-sys | BSD-3-Clause | `sqlcipher/LICENSE` | Yes, compiled from `sqlcipher/sqlite3.c` |
| SQLite | 3.51.3, the base of SQLCipher 4.14.0 | Public domain | None required | Yes |
| OpenSSL (libcrypto) | 3.6.3 | Apache-2.0 | `openssl/LICENSE.txt` | Yes, static `libcrypto.a` (and `libssl.a`, linked by openssl-sys) |
| rusqlite | 0.40.2 | MIT | `rusqlite/LICENSE` | Yes |
| libsqlite3-sys | 0.38.2 | MIT | `libsqlite3-sys/LICENSE` | Yes |
| openssl-sys | 0.9.117 | MIT | `openssl-sys/LICENSE-MIT` | Yes |
| openssl-src | 300.6.1+3.6.3 | MIT (choice from MIT/Apache-2.0) | `openssl-src/LICENSE-MIT` | No. Build script only. It supplies the OpenSSL source. |

### SQLCipher notice

The SQLCipher source in the binary has this notice (`sqlcipher/sqlite3.c`, file `sqlcipher.c`).
The file `sqlcipher/LICENSE` has the same terms with the years 2008-2020.

```
SQLCipher
http://zetetic.net

Copyright (c) 2008-2024, ZETETIC LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the ZETETIC LLC nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### SQLite notice

The SQLite authors disclaim copyright to the SQLite source code. In place of a legal notice, SQLite gives this blessing:

```
May you do good and not evil.
May you find forgiveness for yourself and forgive others.
May you share freely, never taking more than you give.
```

The xoshiro256++ generator in SQLCipher is also public domain (source comment in `sqlite3.c`). SQLCipher does not use it for cryptography.

### OpenSSL notice

OpenSSL 3.6.3 is licensed under the Apache License 2.0. The full text is in `openssl/LICENSE.txt`.
OpenSSL 3.6.3 has no `NOTICE` file. The advertising clause of the old OpenSSL license does not apply to OpenSSL 3.

```
Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
Licensed under the Apache License 2.0.
```

The copyright years in the source headers differ by file. The range above is the range of the headers in `crypto/`, `providers/`, `ssl/`, and `include/` of OpenSSL 3.6.3. The license text is the binding part.

## TLS stack

These crates are linked on macOS (`cargo tree --target aarch64-apple-darwin`). `webpki-root-certs` and `rustls-native-certs` are in `Cargo.lock`, but they are not linked on macOS.

| Component | Version | License used | Text |
| --- | --- | --- | --- |
| rustls | 0.23.44 | MIT (choice from Apache-2.0 OR ISC OR MIT) | `rustls/LICENSE-MIT` |
| ring | 0.17.14 | Apache-2.0 AND ISC | `ring/LICENSE`, `ring/LICENSE-other-bits` (ISC), `ring/LICENSE-BoringSSL` (Apache-2.0 and other BoringSSL notices), `ring/LICENSE-once_cell-MIT` |
| rustls-webpki | 0.103.15 | ISC | `rustls-webpki/LICENSE` |
| rustls-platform-verifier | 0.7.0 | MIT (choice from MIT OR Apache-2.0) | `rustls-platform-verifier/LICENSE-MIT` |
| rustls-pki-types | 1.15.1 | MIT (choice from MIT OR Apache-2.0) | `rustls-pki-types/LICENSE-MIT` |
| untrusted | 0.9.0 | ISC | `untrusted/LICENSE.txt` |
| subtle | 2.6.1 | BSD-3-Clause | `subtle/LICENSE` |
| zeroize | 1.9.0 | MIT (choice from Apache-2.0 OR MIT) | `zeroize/LICENSE-MIT` |
| security-framework, security-framework-sys | 3.7.0, 2.17.0 | MIT (choice from MIT OR Apache-2.0) | `security-framework/LICENSE-MIT` (same text in both crates) |
| core-foundation, core-foundation-sys | 0.10.1, 0.8.7 | MIT (choice from MIT OR Apache-2.0) | `core-foundation/LICENSE-MIT` (same text in both crates) |

## eframe and egui

| Component | Version | License used | Text |
| --- | --- | --- | --- |
| eframe, egui, epaint, emath, egui-winit, egui_glow | 0.36.2 | MIT (choice from MIT OR Apache-2.0) | `egui/LICENSE-MIT` |
| epaint_default_fonts (code) | 0.36.2 | MIT (choice from MIT OR Apache-2.0) | `egui/LICENSE-MIT` |

The `default_fonts` feature embeds four fonts in the binary:

| Font file | License | Text |
| --- | --- | --- |
| `Hack-Regular.ttf` | MIT (Source Foundry Authors), Bitstream Vera License, DejaVu public domain | `egui-default-fonts/Hack-Regular.txt` |
| `NotoEmoji-Regular.ttf` | SIL Open Font License 1.1 | `egui-default-fonts/OFL.txt` |
| `Ubuntu-Light.ttf` | Ubuntu Font Licence 1.0 | `egui-default-fonts/UFL.txt` |
| `emoji-icon-font.ttf` | MIT (John Slegers) | `egui-default-fonts/emoji-icon-font-mit-license.txt` |

The OFL and the Ubuntu Font Licence permit embedding in an application. They do not permit the sale of the font files alone. Reserved font names ("Bitstream", "Vera") must not be used for a modified font.

## Patent notices

- Apache-2.0 (OpenSSL, the BoringSSL parts of ring) includes a patent license from each contributor (section 3). The license ends for a party that starts patent litigation about the work.
- BSD-3-Clause, MIT, ISC, OFL, and the Ubuntu Font Licence have no patent grant.
- The only patent text in the OpenSSL 3.6.3 source is a prior-art comment in `crypto/ec/ec2_oct.c` about binary-field point compression. SQLCipher does not use that code.
- The SQLCipher and SQLite sources have no patent notice.
