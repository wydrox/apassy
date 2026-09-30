import cargo from "../../../Cargo.toml?raw";

export const REPO = "https://github.com/wydrox/apassy";
export const DOWNLOAD = "/download/Apassy.dmg";
/** The version of the app, from Cargo.toml at build time. */
export const VERSION = cargo.match(/^version = "([^"]+)"/m)?.[1] ?? "";
/** The installer (scripts/install.sh, served by src/pages/install.sh.ts). */
export const INSTALL_URL = "https://apassy.wyderka.cc/install.sh";
export const INSTALL_COMMAND = `/bin/bash -c "$(curl -fsSL ${INSTALL_URL})"`;
