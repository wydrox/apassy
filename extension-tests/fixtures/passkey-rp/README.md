# Synthetic passkey checks

The fixture uses a local test account. It does not open a user's vault.

From `extension-tests`, run:

```sh
npm run passkey-rp:check
npm run passkey-rp:core-check
```

The first command checks the test server. The second command builds the Rust driver and checks actual Apassy vault responses with `@simplewebauthn/server`.

The core check covers registration, sign-in, a vault reopen, and an encrypted backup and restore. It also checks rejection of damaged signatures, a wrong origin, a wrong RP ID, and a wrong credential ID.

These checks verify cryptography and encrypted storage. They do not verify browser controls, owner checks, AutoFill, Face ID, or delivery through iCloud.

To start the test page, run:

```sh
npm run passkey-rp:start -- --port 4173
```

Open `http://localhost:4173/`. Use `?transform=manual` to check the manual JSON conversion path.
