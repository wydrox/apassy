//! Builds or finds `libtailscale.a` for the feature `tailnet` (ADR 0037 D9, plan s4 T0).
//!
//! Without the feature, nothing happens: the crate builds without Go.
//! With it, in this order:
//! 1. `APASSY_LIBTAILSCALE_DIR` names a directory with a prebuilt `libtailscale.a`
//!    (and optionally `libtailscale.ldflags`, one link flag per line). CI builds it once
//!    with `scripts/build-archive.sh` and passes it to the cargo builds.
//! 2. Else the pinned Go (`pins.env`; `APASSY_TAILNET_GO` or `go` on `PATH`) builds the
//!    vendored package in `go/`: `CGO_ENABLED=1 go build -trimpath -buildvcs=false
//!    -buildmode=c-archive`, with `GOTOOLCHAIN=local` and `GOFLAGS=-mod=readonly`, so
//!    the `go.sum` of the pinned commit decides every module and nothing is downloaded
//!    as a toolchain.
//! 3. Else the build fails: "the embedded tailnet needs Go or a prebuilt archive".
//!
//! The link flags are the `#cgo LDFLAGS` of every package in the archive (`go list`),
//! plus the frameworks and libraries that the Go standard library imports dynamically
//! on macOS (CoreFoundation, Security, libresolv), which `go list` does not show.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

const NEEDS_GO: &str = "the embedded tailnet needs Go or a prebuilt archive";

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let go_dir = manifest.join("go");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=pins.env");
    println!("cargo:rerun-if-changed=go");
    for name in [
        "APASSY_LIBTAILSCALE_DIR",
        "APASSY_TAILNET_GO",
        "APASSY_TAILNET_ANY_GO",
        "APASSY_TAILNET_GO_TAGS",
        "APASSY_TAILNET_REPORT",
        "MACOSX_DEPLOYMENT_TARGET",
        "CGO_CFLAGS",
        "CGO_LDFLAGS",
        "CC",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_TAILNET").is_none() {
        return;
    }

    let pins = read_pins(&manifest.join("pins.env"));
    let pin = |key: &str| -> String {
        pins.get(key)
            .cloned()
            .unwrap_or_else(|| panic!("pins.env has no {key}"))
    };
    let target = Target::from_cargo();
    let deployment_target = env::var("MACOSX_DEPLOYMENT_TARGET")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| pin("MACOS_DEPLOYMENT_TARGET"));

    let (archive_dir, flags, source) = match env::var_os("APASSY_LIBTAILSCALE_DIR") {
        Some(dir) if !dir.is_empty() => {
            let dir = PathBuf::from(dir);
            let archive = dir.join("libtailscale.a");
            if !archive.is_file() {
                panic!(
                    "{NEEDS_GO}: APASSY_LIBTAILSCALE_DIR is {}, but it has no libtailscale.a",
                    dir.display()
                );
            }
            println!("cargo:rerun-if-changed={}", archive.display());
            let listed = dir.join("libtailscale.ldflags");
            let flags = if listed.is_file() {
                println!("cargo:rerun-if-changed={}", listed.display());
                fs::read_to_string(&listed)
                    .unwrap_or_else(|error| panic!("cannot read {}: {error}", listed.display()))
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect()
            } else {
                Vec::new()
            };
            (dir, flags, "prebuilt")
        }
        _ => {
            let go = Go::find(&pin("GO_VERSION"));
            go.check_host(&target);
            let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("libtailscale");
            fs::create_dir_all(&out)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", out.display()));
            let flags = go.build(&go_dir, &out, &target, &deployment_target);
            fs::write(out.join("libtailscale.ldflags"), flags.join("\n") + "\n")
                .expect("write libtailscale.ldflags");
            (out, flags, "built with Go")
        }
    };

    let mut links = LinkFlags::default();
    for flag in target.default_flags() {
        links.add_token_list(&[flag.to_string()]);
    }
    links.add_token_list(&flags);

    println!("cargo:rustc-link-search=native={}", archive_dir.display());
    println!("cargo:rustc-link-lib=static=tailscale");
    for directive in &links.directives {
        println!("cargo:{directive}");
    }
    let summary = links.summary.join(" ");
    println!("cargo:rustc-env=APASSY_TAILNET_LINK_FLAGS={summary}");
    println!("cargo:rustc-env=APASSY_TAILNET_ARCHIVE_SOURCE={source}");
    println!(
        "cargo:rustc-env=APASSY_TAILNET_LIBTAILSCALE_COMMIT={}",
        pin("LIBTAILSCALE_COMMIT")
    );
    println!(
        "cargo:rustc-env=APASSY_TAILNET_GO_VERSION={}",
        pin("GO_VERSION")
    );
    println!(
        "cargo:rustc-env=APASSY_TAILNET_TAILSCALE_VERSION={}",
        pin("TAILSCALE_VERSION")
    );
    if env::var_os("APASSY_TAILNET_REPORT").is_some() {
        let archive = archive_dir.join("libtailscale.a");
        let size = fs::metadata(&archive).map(|meta| meta.len()).unwrap_or(0);
        println!(
            "cargo:warning=apassy-tailnet: {source} {} ({size} bytes); link flags: {summary}",
            archive.display()
        );
        for ignored in &links.ignored {
            println!("cargo:warning=apassy-tailnet: ignored link flag {ignored}");
        }
    }
}

/// `KEY=VALUE` lines; `#` starts a comment line.
fn read_pins(path: &Path) -> BTreeMap<String, String> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

struct Target {
    goos: &'static str,
    goarch: &'static str,
}

impl Target {
    fn from_cargo() -> Self {
        let os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS");
        let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
        let goos = match os.as_str() {
            "macos" => "darwin",
            "linux" => "linux",
            other => panic!("the embedded tailnet supports macOS and Linux, not {other}"),
        };
        let goarch = match arch.as_str() {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => panic!("the embedded tailnet supports arm64 and x86_64, not {other}"),
        };
        Self { goos, goarch }
    }

    /// What the Go standard library needs at link time beyond `#cgo LDFLAGS`.
    /// macOS: `//go:cgo_import_dynamic` of crypto/x509 (Security, CoreFoundation) and
    /// of the resolver (libresolv). Linux: the pthread library of runtime/cgo (glibc
    /// 2.31 keeps it separate from libc).
    fn default_flags(&self) -> &'static [&'static str] {
        match self.goos {
            "darwin" => &[
                "-framework CoreFoundation",
                "-framework Security",
                "-lresolv",
            ],
            _ => &["-lpthread"],
        }
    }
}

struct Go {
    program: String,
    host_os: String,
    host_arch: String,
}

impl Go {
    fn find(pinned: &str) -> Self {
        let program = env::var("APASSY_TAILNET_GO")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "go".to_owned());
        let output = match Command::new(&program)
            .args(["env", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"])
            .env("GOTOOLCHAIN", "local")
            .output()
        {
            Ok(output) if output.status.success() => output,
            Ok(output) => panic!(
                "{NEEDS_GO}: `{program} env` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => panic!(
                "{NEEDS_GO}: no `{program}` on PATH. Install Go {pinned} \
                 (crates/apassy-tailnet/scripts/install-go.sh), or set APASSY_LIBTAILSCALE_DIR \
                 to a directory with libtailscale.a, or build without the feature `tailnet`."
            ),
            Err(error) => panic!("{NEEDS_GO}: cannot run `{program}`: {error}"),
        };
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let mut lines = text.lines().map(str::trim);
        let version = lines.next().unwrap_or_default().to_owned();
        let host_os = lines.next().unwrap_or_default().to_owned();
        let host_arch = lines.next().unwrap_or_default().to_owned();
        let wanted = format!("go{pinned}");
        if version != wanted {
            if env::var_os("APASSY_TAILNET_ANY_GO").is_some() {
                println!(
                    "cargo:warning=apassy-tailnet: building with {version}, not the pinned {wanted} \
                     (APASSY_TAILNET_ANY_GO is set); the archive is not the reviewed build"
                );
            } else {
                panic!(
                    "the embedded tailnet is pinned to {wanted}, and `{program}` is {version}. \
                     Install the pinned Go (crates/apassy-tailnet/scripts/install-go.sh) and put \
                     it first on PATH or in APASSY_TAILNET_GO, or set APASSY_TAILNET_ANY_GO=1 for \
                     a local experiment."
                );
            }
        }
        Self {
            program,
            host_os,
            host_arch,
        }
    }

    fn check_host(&self, target: &Target) {
        if self.host_os != target.goos || self.host_arch != target.goarch {
            panic!(
                "{NEEDS_GO}: Go runs on {}/{}, the target is {}/{}. A cross build needs a \
                 prebuilt archive in APASSY_LIBTAILSCALE_DIR.",
                self.host_os, self.host_arch, target.goos, target.goarch
            );
        }
    }

    fn command(&self, go_dir: &Path, target: &Target, deployment_target: &str) -> Command {
        let mut command = Command::new(&self.program);
        command
            .current_dir(go_dir)
            .env("CGO_ENABLED", "1")
            .env("GOTOOLCHAIN", "local")
            .env("GOFLAGS", "-mod=readonly")
            .env("GOOS", target.goos)
            .env("GOARCH", target.goarch);
        if target.goos == "darwin" {
            let min = format!("-mmacosx-version-min={deployment_target}");
            let join = |name: &str| match env::var(name) {
                Ok(existing) if !existing.is_empty() => format!("{existing} {min}"),
                _ => min.clone(),
            };
            command
                .env("MACOSX_DEPLOYMENT_TARGET", deployment_target)
                .env("CGO_CFLAGS", join("CGO_CFLAGS"))
                .env("CGO_LDFLAGS", join("CGO_LDFLAGS"));
        }
        command
    }

    /// Builds `out/libtailscale.a` and returns the `#cgo LDFLAGS` tokens of its packages.
    fn build(
        &self,
        go_dir: &Path,
        out: &Path,
        target: &Target,
        deployment_target: &str,
    ) -> Vec<String> {
        let tags = env::var("APASSY_TAILNET_GO_TAGS").unwrap_or_default();
        let mut build = self.command(go_dir, target, deployment_target);
        build.args([
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-buildmode=c-archive",
        ]);
        if !tags.trim().is_empty() {
            build.args(["-tags", tags.trim()]);
        }
        build.arg("-o").arg(out.join("libtailscale.a")).arg(".");
        run(build, "go build");

        let mut list = self.command(go_dir, target, deployment_target);
        list.args(["list", "-deps"]);
        if !tags.trim().is_empty() {
            list.args(["-tags", tags.trim()]);
        }
        list.args(["-f", "{{join .CgoLDFLAGS \"\\n\"}}", "."]);
        run(list, "go list")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

/// Runs a Go command. Its output never reaches the build script's stdout, where Cargo
/// reads directives.
fn run(mut command: Command, what: &str) -> String {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{NEEDS_GO}: cannot run {what}: {error}"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        panic!(
            "{what} of the vendored libtailscale failed ({}):\n{stderr}",
            output.status
        );
    }
    if !stderr.trim().is_empty() {
        eprintln!("{what}: {stderr}");
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Cargo directives from `-l`, `-framework`, `-L`, and `-pthread` link flags.
#[derive(Default)]
struct LinkFlags {
    directives: Vec<String>,
    summary: Vec<String>,
    ignored: Vec<String>,
}

impl LinkFlags {
    fn add_token_list(&mut self, lines: &[String]) {
        let tokens: Vec<&str> = lines
            .iter()
            .flat_map(|line| line.split_whitespace())
            .collect();
        let mut index = 0;
        while index < tokens.len() {
            let token = tokens[index];
            index += 1;
            let (directive, shown) = if token == "-framework" {
                let Some(name) = tokens.get(index) else {
                    self.ignored.push(token.to_owned());
                    continue;
                };
                index += 1;
                (
                    format!("rustc-link-lib=framework={name}"),
                    format!("-framework {name}"),
                )
            } else if let Some(name) = token.strip_prefix("-l") {
                (format!("rustc-link-lib={name}"), token.to_owned())
            } else if let Some(dir) = token.strip_prefix("-L") {
                (format!("rustc-link-search=native={dir}"), token.to_owned())
            } else if token == "-pthread" {
                ("rustc-link-lib=pthread".to_owned(), "-lpthread".to_owned())
            } else {
                self.ignored.push(token.to_owned());
                continue;
            };
            if !self.directives.contains(&directive) {
                self.directives.push(directive);
                self.summary.push(shown);
            }
        }
    }
}
