import cargo from "../../../Cargo.toml?raw";

export const REPO = "https://github.com/wydrox/apassy";
export const DOWNLOAD = "/download/Apassy.dmg";
/** The version of the app, from Cargo.toml at build time. */
export const VERSION = cargo.match(/^version = "([^"]+)"/m)?.[1] ?? "";
/** The installer (scripts/install.sh, served by src/pages/install.sh.ts). */
export const INSTALL_URL = "https://apassy.wyderka.cc/install.sh";
export const INSTALL_COMMAND = `/bin/bash -c "$(curl -fsSL ${INSTALL_URL})"`;
/** The team CLI (apassy-team) of the Apassy relay: the build for Linux and its installer. */
export const RELAY = "https://apassy-relay.wyderka.cc";
export const TEAM_CLI_LINUX = `${RELAY}/dl/apassy-team-linux-x86_64`;
export const TEAM_CLI_SUMS = `${RELAY}/dl/SHA256SUMS`;
export const TEAM_CLI_GUIDE = `${RELAY}/guide`;
export const TEAM_INSTALL_COMMAND = `curl -fsSL ${RELAY}/install.sh -o install.sh && sh install.sh`;
