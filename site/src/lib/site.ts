import changelog from "../../../CHANGELOG.md?raw";

export const REPO = "https://github.com/wydrox/apassy";
export const DOWNLOAD = "/download/Apassy.dmg";
/** The browser extension in the Chrome Web Store (ADR 0021, D5). */
export const EXTENSION_STORE = "https://chromewebstore.google.com/detail/apassy/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";
/**
 * The newest released version of the app: the first dated section of CHANGELOG.md at
 * build time. Cargo.toml can name a version that is not published yet, so it is not used.
 */
export const VERSION = changelog.match(/^## \[(\d+\.\d+\.\d+[^\]\s]*)\] - \d{4}-\d{2}-\d{2}[ \t]*$/m)?.[1] ?? "";
/** The installer (scripts/install.sh, served by src/pages/install.sh.ts). */
export const INSTALL_URL = "https://apassy.wyderka.cc/install.sh";
export const INSTALL_COMMAND = `/bin/bash -c "$(curl -fsSL ${INSTALL_URL})"`;
/** The team CLI (apassy-team) of the Apassy relay: the build for Linux and its installer. */
export const RELAY = "https://apassy-relay.wyderka.cc";
export const TEAM_CLI_LINUX = `${RELAY}/dl/apassy-team-linux-x86_64`;
export const TEAM_CLI_SUMS = `${RELAY}/dl/SHA256SUMS`;
export const TEAM_CLI_GUIDE = `${RELAY}/guide`;
export const TEAM_INSTALL_COMMAND = `curl -fsSL ${RELAY}/install.sh -o install.sh && sh install.sh`;
