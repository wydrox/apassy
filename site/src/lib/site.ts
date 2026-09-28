import cargo from "../../../Cargo.toml?raw";

export const REPO = "https://github.com/wydrox/apassy";
export const DOWNLOAD = "/download/Apassy.dmg";
/** The version of the app, from Cargo.toml at build time. */
export const VERSION = cargo.match(/^version = "([^"]+)"/m)?.[1] ?? "";
