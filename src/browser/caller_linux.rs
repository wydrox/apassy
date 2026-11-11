//! Linux's browser check is defense in depth, not executable authentication of a
//! hardened socket peer. SO_PEERCRED authenticates its PID and user. We verify its
//! direct browser parent and refuse unreadable/stale process information. Linux
//! prevents reading a non-dumpable peer's exe; that one PermissionDenied case uses
//! the kernel ancestry, never a claimed process name or request PID. The host checks
//! its own image before relaying. Compromised same-user processes, including injected
//! browser subprocesses, remain outside this software vault's protection (ADR 0045).
//!
//! The browser must share Apassy's mount and user namespaces, so that the paths and
//! owners that Apassy checks are the ones that the browser used. Its switches are
//! read from its process title only: the environment, the wrapper's configuration,
//! the profile and policy files never appear there, so the switch check is best
//! effort against another program of the same user (ADR 0045, "What the switch check
//! sees").

use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use super::WireError;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
pub(in crate::browser) const HOST: &str = "/usr/lib/apassy/apassy-browser-host";
/// The packaged browser executables that the check accepts. `install` names the same
/// paths when it tells a supported browser from a snap or Flatpak.
pub(in crate::browser) const BROWSERS: &[&str] = &[
    "/opt/google/chrome/chrome",
    "/usr/lib/chromium/chromium",
    "/usr/lib/chromium-browser/chromium-browser",
];
#[cfg(target_os = "linux")]
const MAX_PROC_BYTES: u64 = 128 * 1024;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Process {
    parent: u32,
    start: u64,
    uids: [u32; 4],
}

fn invalid() -> io::Error {
    io::Error::other("unverifiable browser process")
}

/// `comm` can contain spaces and parentheses; the rightmost `) ` ends it. State is
/// field 3, parent field 4, and starttime field 22. Never use comm as identity.
fn parse_stat(text: &str) -> io::Result<(u32, u64)> {
    let (_, fields) = text.rsplit_once(") ").ok_or_else(invalid)?;
    let fields: Vec<_> = fields.split_ascii_whitespace().collect();
    if fields.len() < 20 || !matches!(fields[0], "R" | "S" | "D" | "T" | "t" | "I") {
        return Err(invalid());
    }
    let parent = fields[1].parse::<u32>().map_err(|_| invalid())?;
    let start = fields[19].parse::<u64>().map_err(|_| invalid())?;
    if parent == 0 || start == 0 {
        return Err(invalid());
    }
    Ok((parent, start))
}

fn parse_uids(text: &str) -> io::Result<[u32; 4]> {
    let mut lines = text.lines().filter_map(|line| line.strip_prefix("Uid:\t"));
    let values = lines.next().ok_or_else(invalid)?;
    if lines.next().is_some() {
        return Err(invalid());
    }
    let values: Vec<_> = values.split_ascii_whitespace().collect();
    if values.len() != 4 {
        return Err(invalid());
    }
    let mut uids = [0; 4];
    for (value, uid) in values.into_iter().zip(&mut uids) {
        *uid = value.parse().map_err(|_| invalid())?;
    }
    Ok(uids)
}

#[cfg(target_os = "linux")]
fn bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_PROC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROC_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn process(pid: u32, uid: u32) -> io::Result<Process> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = bounded(&root.join("stat"))?;
    let (parent, start) = parse_stat(std::str::from_utf8(&stat).map_err(|_| invalid())?)?;
    let status = bounded(&root.join("status"))?;
    let uids = parse_uids(std::str::from_utf8(&status).map_err(|_| invalid())?)?;
    if uids != [uid; 4] {
        return Err(invalid());
    }
    Ok(Process {
        parent,
        start,
        uids,
    })
}

fn safe_mode(uid: u32, mode: u32, file: bool) -> bool {
    uid == 0 && mode & 0o022 == 0 && (!file || (mode & 0o111 != 0 && mode & 0o6000 == 0))
}

/// Every path component must be root-owned and non-writable by group/others. No
/// symlinks, set-ID executables, deleted images, relative paths or source builds.
pub(in crate::browser) fn trusted_binary(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid());
    }
    for (index, component) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(component)?;
        let file = index == 0;
        if !safe_mode(metadata.uid(), metadata.mode(), file)
            || (file && !metadata.is_file())
            || (!file && !metadata.is_dir())
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn image(pid: u32, expected: &[&str]) -> io::Result<PathBuf> {
    let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
    let path = fs::read_link(&proc_exe)?;
    if !expected
        .iter()
        .any(|candidate| path == Path::new(candidate))
    {
        return Err(invalid());
    }
    trusted_binary(&path)?;
    let executing = fs::metadata(&proc_exe)?;
    let installed = fs::metadata(&path)?;
    if (executing.dev(), executing.ino()) != (installed.dev(), installed.ino()) {
        return Err(invalid());
    }
    Ok(path)
}

/// The folder where Debian's `chromium` package (and the `webext-*` packages that it
/// loads) keep system extensions, relative to the file system root. Debian's
/// `/etc/chromium.d/extensions` starts Chromium with `--load-extension=` and the
/// comma-separated list `ls -dm /usr/share/chromium/extensions/*` (observed on Debian
/// 13, chromium 156). An empty folder gives an empty value, which stays refused.
const SYSTEM_EXTENSIONS: &str = "usr/share/chromium/extensions";

/// Where [`safe_arguments_in`] looks for system extensions, and whose they must be.
/// Production uses `/` and root ([`Trust::system`]); tests use a private temporary
/// folder and their own user, because they cannot create root-owned files.
#[derive(Debug, Clone, Copy)]
struct Trust<'a> {
    root: &'a Path,
    owner: u32,
}

impl Trust<'static> {
    fn system() -> Self {
        Self {
            root: Path::new("/"),
            owner: 0,
        }
    }
}

/// True when `value`, the whole value of one `--load-extension` switch, names only
/// system extensions: one or more comma-separated absolute paths, each of which,
/// after resolving symlinks, is a directory strictly inside [`SYSTEM_EXTENSIONS`].
/// That folder, each named directory and every folder above them up to the root are
/// owned by `trust.owner` and not writable by group or others. So only the owner of
/// the browser binary (root) can choose what this switch loads: the same trust as the
/// root-owned browser executable itself. An empty value, an empty item, a relative
/// path, a missing path, a file, the folder itself and every path outside it are
/// refused.
fn system_extensions(value: &[u8], trust: Trust<'_>) -> bool {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    if value.is_empty() {
        return false;
    }
    let Ok(root) = fs::canonicalize(trust.root) else {
        return false;
    };
    // `path` (canonical, under `root`) and every folder above it up to `root`, which
    // is included: directories of the trusted owner, not writable by group or others.
    let owned = |path: &Path| {
        path.starts_with(&root)
            && path
                .ancestors()
                .take_while(|p| p.starts_with(&root))
                .all(|p| {
                    fs::symlink_metadata(p).is_ok_and(|metadata| {
                        metadata.is_dir()
                            && metadata.uid() == trust.owner
                            && metadata.mode() & 0o022 == 0
                    })
                })
    };
    let Ok(folder) = fs::canonicalize(root.join(SYSTEM_EXTENSIONS)) else {
        return false;
    };
    if !owned(&folder) {
        return false;
    }
    value.split(|b| *b == b',').all(|item| {
        let Some(relative) = item.strip_prefix(b"/").filter(|rest| !rest.is_empty()) else {
            return false;
        };
        let Ok(real) = fs::canonicalize(root.join(OsStr::from_bytes(relative))) else {
            return false;
        };
        real != folder && real.starts_with(&folder) && owned(&real)
    })
}

/// Switches that refuse a browser in every case, whatever their value: they let
/// another program control the browser, load code into it, replace the programs it
/// starts for its pages, or silently weaken how it treats pages and certificates, so
/// the origin that the extension reports could be another site's. Names are compared
/// in lower case, without the leading dashes and the value.
///
/// Chosen from the switch definitions of Chromium (main branch, read 2026-11-11):
///
/// - Code by path, and more power for extensions: `extensions/common/switches.cc`
///   (`load-extension` has its own rule below, `disable-extensions-except`,
///   `load-apps`, `allowlisted-extension-id`, `extensions-on-chrome-urls`,
///   `extensions-on-extension-urls`, `extension-test-api-on-web-pages`),
///   `chrome/common/chrome_switches.h` (`install-isolated-web-app-from-file`,
///   `install-isolated-web-app-from-url`, `custom-devtools-frontend`), and
///   `content/public/common/content_switches.cc` (`load-webui-from-disk`).
/// - Automation: `content/public/common/content_switches.cc` (`remote-debugging-*`,
///   see [`REFUSED_PREFIXES`], `remote-allow-origins`, `enable-automation`,
///   `dom-automation`, `test-type`) and `chrome/common/chrome_switches.h`
///   (`remote-debugging-targets`, `silent-debugger-extension-api`).
/// - The browser's own programs: `content/public/common/content_switches.cc`
///   (`type`, which only child processes carry, `browser-subprocess-path`,
///   `renderer-cmd-prefix`, `utility-cmd-prefix`, `zygote-cmd-prefix`,
///   `gpu-launcher`, `enable-service-binary-launcher`).
/// - Pages and certificates: `content/public/common/content_switches.cc`
///   (`disable-web-security`, `allow-file-access-from-files`,
///   `allow-insecure-localhost`, `use-mock-cert-verifier-for-testing`,
///   `mock-cert-verifier-default-result-for-testing`),
///   `components/network_session_configurator/common/network_switch_list.h`
///   (`ignore-certificate-errors`), `services/network/public/cpp/network_switches.cc`
///   (`ignore-certificate-errors-spki-list`, `unsafely-treat-insecure-origin-as-secure`,
///   `ssl-key-log-file`) and `chrome/common/chrome_switches.h`
///   (`allow-running-insecure-content`).
/// - Host and resolver rules: `services/network/public/cpp/network_switches.cc`
///   (`host-resolver-rules`, `host-rules`).
///
/// The switches that turn off the browser's sandbox or its site isolation are in
/// [`WEAKENING_SWITCHES`]; they refuse too, with a message that names them.
///
/// Switches for the display, the GPU, the language, the profile folder, the password
/// store or a proxy stay accepted (see the test
/// `ordinary_linux_switches_are_accepted`): refusing them would break real users.
const REFUSED_SWITCHES: &[&str] = &[
    // Code by path, and more power for extensions.
    "disable-extensions-except",
    "load-apps",
    "allowlisted-extension-id",
    "extensions-on-chrome-urls",
    "extensions-on-extension-urls",
    "extension-test-api-on-web-pages",
    "install-isolated-web-app-from-file",
    "install-isolated-web-app-from-url",
    "custom-devtools-frontend",
    "load-webui-from-disk",
    // Automation.
    "remote-allow-origins",
    "enable-automation",
    "dom-automation",
    "test-type",
    "silent-debugger-extension-api",
    // The browser's own programs.
    "type",
    "browser-subprocess-path",
    "renderer-cmd-prefix",
    "utility-cmd-prefix",
    "zygote-cmd-prefix",
    "gpu-launcher",
    "enable-service-binary-launcher",
    // Pages and certificates.
    "disable-web-security",
    "allow-file-access-from-files",
    "allow-insecure-localhost",
    "use-mock-cert-verifier-for-testing",
    "mock-cert-verifier-default-result-for-testing",
    "ignore-certificate-errors",
    "ignore-certificate-errors-spki-list",
    "unsafely-treat-insecure-origin-as-secure",
    "ssl-key-log-file",
    "allow-running-insecure-content",
    // Host and resolver rules.
    "host-resolver-rules",
    "host-rules",
];

/// Every switch that starts with one of these is refused: `remote-debugging-port`,
/// `-pipe`, `-address`, `-socket-name`, `-io-pipes`, `-targets` and any later one.
const REFUSED_PREFIXES: &[&str] = &["remote-debugging"];

/// Switches that turn off the browser's sandbox or its site isolation, or hand flags to
/// its JavaScript engine: a page could then reach the memory of another site's page,
/// whose origin the extension reports. They refuse every browser, whatever their
/// value, and the refusal names the switch ([`super::weakened`]). From the switch
/// definitions of Chromium (main branch, read 2026-11-11): `sandbox/policy/switches.cc`
/// (`no-sandbox`, `disable-setuid-sandbox`), `content/public/common/content_switches.cc`
/// (`disable-site-isolation-trials`, `disable-site-isolation-for-policy`) and
/// `third_party/blink/common/switches.cc` (`js-flags`). `--disable-features` follows
/// [`weakening_features`].
const WEAKENING_SWITCHES: &[&str] = &[
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-site-isolation-trials",
    "--disable-site-isolation-for-policy",
    "--js-flags",
];

/// Words in the names of features that keep sites apart or sandbox a process, in lower
/// case. Disabling such a feature refuses the browser. From the feature definitions of
/// Chromium (main branch, read 2026-11-11): `content/public/common/content_features.cc`
/// (`IsolateOrigins`, `OriginIsolationHeader`, `StrictOriginIsolation`,
/// `OriginKeyedProcessesByDefault`, `SiteIsolationForCrossOriginOpenerPolicy`,
/// `IsolateSubframeErrorPages`, `IsolateFencedFrames`, `SpareRendererForSitePerProcess`,
/// `AudioServiceSandbox`), `components/site_isolation/features.cc`
/// (`site-isolation-for-password-sites`, `SiteIsolationForOAuthSites`,
/// `IsolateOriginsShortlistPolicyUpdate`, `OriginIsolationForJitlessExceptions`) and
/// `sandbox/policy/features.cc` (`NetworkServiceSandbox`,
/// `OnDeviceModelExecutionMultiThreadedSandbox`). A word, not the exact names, so that
/// a later feature of the same kind refuses too. The Privacy Sandbox (ads APIs) is no
/// process sandbox: [`PRIVACY_SANDBOX`] stays accepted.
const WEAKENING_FEATURE_WORDS: &[&str] = &[
    "isolat",
    "siteperprocess",
    "originkeyedprocesses",
    "sandbox",
];

/// The start of the names of the Privacy Sandbox features (`PrivacySandboxAdsAPIs…`),
/// in lower case: ads APIs, which owners turn off for privacy.
const PRIVACY_SANDBOX: &str = "privacysandbox";

/// True when the value of `--disable-features` names a feature of
/// [`WEAKENING_FEATURE_WORDS`]. Each comma-separated name is compared without the
/// `*` of a default state and without a field trial (`<…`) or parameters (`:…`), in
/// lower case.
fn weakening_features(value: &[u8]) -> bool {
    value.split(|b| *b == b',').any(|entry| {
        let entry = entry.strip_prefix(b"*").unwrap_or(entry);
        let name = entry
            .iter()
            .take_while(|b| !matches!(b, b'<' | b':'))
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>();
        !name.starts_with(PRIVACY_SANDBOX.as_bytes())
            && WEAKENING_FEATURE_WORDS
                .iter()
                .any(|word| name.windows(word.len()).any(|w| w == word.as_bytes()))
    })
}

/// The switch of one title word that turns off the sandbox or site isolation, as the
/// refusal names it (`--no-sandbox`), or `None`.
fn weakening(word: &[u8], name: &[u8]) -> Option<&'static str> {
    if name == b"disable-features" && weakening_features(switch_value(word)) {
        return Some("--disable-features");
    }
    WEAKENING_SWITCHES
        .iter()
        .copied()
        .find(|s| name == s.trim_start_matches('-').as_bytes())
}

/// What Debian's `/usr/bin/chromium` and its `/etc/chromium.d/*` (`default-flags`,
/// `dev-shm`, `extensions`; Debian 13, chromium 156.0.8078.79-1~deb13u1) add to every
/// start, besides `--load-extension`. `disable-background-networking` comes only
/// with `--disable-extensions-except`, which stays refused.
const DEBIAN_WRAPPER_SWITCHES: &[&str] = &[
    "show-component-extension-options",
    "enable-gpu-rasterization",
    "no-default-browser-check",
    "disable-pings",
    "media-router",
    "disable-dev-shm-usage",
    "enable-remote-extensions",
    "disable-background-networking",
];

/// The display, GPU and language switches, kept everywhere (unlike
/// [`REFUSED_SWITCHES`]), that may also accompany Debian's system extensions.
/// `enable-features` and `disable-features` follow [`display_features`].
const DISPLAY_SWITCHES: &[&str] = &[
    // Display: Wayland or X11, scale, theme, window.
    "ozone-platform",
    "ozone-platform-hint",
    "enable-wayland-ime",
    "wayland-text-input-version",
    "gtk-version",
    "force-device-scale-factor",
    "force-dark-mode",
    "start-maximized",
    // GPU.
    "disable-gpu",
    "disable-gpu-compositing",
    "disable-gpu-rasterization",
    "ignore-gpu-blocklist",
    "enable-zero-copy",
    "use-gl",
    "use-angle",
    "num-raster-threads",
    // Language.
    "lang",
    "accept-lang",
];

/// The profile, password-store and proxy switches, accepted for every browser, that
/// may also accompany Debian's system extensions: Chromium's own per-profile desktop
/// shortcuts start it with `--profile-directory`. What a profile holds is outside what
/// the check can see in every case (ADR 0045, "What the switch check sees").
const PROFILE_SWITCHES: &[&str] = &[
    "profile-directory",
    "user-data-dir",
    "password-store",
    "proxy-server",
];

/// Chromium names a second profile folder `Profile 1`: the title shows
/// `--profile-directory=Profile` and then the number as a word of its own.
const PROFILE_FOLDER: &[u8] = b"--profile-directory=Profile";

/// Words in the names of display and GPU features (`--enable-features=…`).
const DISPLAY_FEATURES: &[&str] = &["Wayland", "Ozone", "Vaapi", "Vulkan", "AcceleratedVideo"];

/// True when every feature that `value` names is a display or GPU feature: a plain
/// name (letters and digits, no field trial or parameter) with a word of
/// [`DISPLAY_FEATURES`].
fn display_features(value: &[u8]) -> bool {
    !value.is_empty()
        && value.split(|b| *b == b',').all(|name| {
            !name.is_empty()
                && name.iter().all(u8::is_ascii_alphanumeric)
                && DISPLAY_FEATURES
                    .iter()
                    .any(|word| name.windows(word.len()).any(|w| w == word.as_bytes()))
        })
}

/// The switch name of one word of the title: lower case, without the leading dashes
/// and the value. Empty for a word that does not start with `-`, and for `--`.
fn switch_name(word: &[u8]) -> Vec<u8> {
    if word.first() != Some(&b'-') {
        return Vec::new();
    }
    word.iter()
        .copied()
        .skip_while(|b| *b == b'-')
        .take_while(|b| *b != b'=')
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

/// The value of a switch word: what follows the first `=`, else empty.
fn switch_value(word: &[u8]) -> &[u8] {
    word.iter()
        .position(|b| *b == b'=')
        .map_or(&[][..], |at| &word[at + 1..])
}

fn refused_switch(name: &[u8]) -> bool {
    REFUSED_SWITCHES.iter().any(|s| name == s.as_bytes())
        || WEAKENING_SWITCHES
            .iter()
            .any(|s| name == s.trim_start_matches('-').as_bytes())
        || REFUSED_PREFIXES
            .iter()
            .any(|p| name.starts_with(p.as_bytes()))
}

/// True when the word at `index` (0 for the first word), after the word `previous`,
/// may stand next to Debian's system extensions: the browser executable as the first
/// word, a switch of [`DEBIAN_WRAPPER_SWITCHES`], [`DISPLAY_SWITCHES`] or
/// [`PROFILE_SWITCHES`], display features, the number of a `Profile N` folder
/// ([`PROFILE_FOLDER`]), or a plain page address (`http://` or `https://`, which the
/// desktop's `%U` passes).
fn beside_system_extensions(index: usize, previous: &[u8], word: &[u8], name: &[u8]) -> bool {
    if word.first() == Some(&b'-') {
        let listed = |list: &[&str]| list.iter().any(|s| name == s.as_bytes());
        return listed(DEBIAN_WRAPPER_SWITCHES)
            || listed(DISPLAY_SWITCHES)
            || listed(PROFILE_SWITCHES)
            || (matches!(name, b"enable-features" | b"disable-features")
                && display_features(switch_value(word)));
    }
    if index == 0 {
        return BROWSERS.iter().any(|path| word == path.as_bytes());
    }
    if previous == PROFILE_FOLDER && word.iter().all(u8::is_ascii_digit) {
        return true;
    }
    let lower = word.to_ascii_lowercase();
    lower.starts_with(b"http://") || lower.starts_with(b"https://")
}

/// True when [`title_refusal`] accepts the title `bytes` of a browser.
#[cfg(test)]
fn safe_arguments(bytes: &[u8]) -> bool {
    safe_arguments_in(bytes, Trust::system())
}

#[cfg(test)]
fn safe_arguments_in(bytes: &[u8], trust: Trust<'_>) -> bool {
    title_refusal(bytes, trust).is_none()
}

/// Match conservatively, including switches after `--`, single dashes and unusual
/// case. Values are never logged, returned, or used as identity.
///
/// Chrome and Chromium rewrite their process title on Linux: `/proc/PID/cmdline`
/// then holds one NUL-terminated string, the arguments joined with spaces. So every
/// whitespace-separated word of every string is checked, `argv[0]` too. A value that
/// contains a space and a switch-like word is refused: this refuses more than the
/// browser reads, never less. Every switch of [`REFUSED_SWITCHES`] and
/// [`REFUSED_PREFIXES`] refuses the browser.
///
/// `--load-extension` is accepted only for system extensions ([`system_extensions`]),
/// with one value: a second occurrence must repeat it exactly. The joined title hides
/// where an argument ends, so a value with a space could go on into the next words,
/// and Chrome splits the whole value at commas. So with that switch present, a comma
/// in any other word refuses the browser. And with it, the title may hold nothing but
/// what [`beside_system_extensions`] allows: an allow list, not a block list, because
/// this is the one case where a loading switch is accepted.
///
/// Returns why the title refuses the browser, or `None` when it is accepted. A switch
/// of [`WEAKENING_SWITCHES`] or a weakening `--disable-features` gives
/// [`Refusal::Weakened`], wherever it is; everything else the generic refusal.
fn title_refusal(bytes: &[u8], trust: Trust<'_>) -> Option<Refusal> {
    if bytes.is_empty() || bytes.last() != Some(&0) {
        return Some(Refusal::Unverifiable);
    }
    let words = || {
        bytes
            .split(|b| *b == 0 || b.is_ascii_whitespace())
            .filter(|word| !word.is_empty())
    };
    if let Some(switch) = words().find_map(|word| weakening(word, &switch_name(word))) {
        return Some(Refusal::Weakened(switch));
    }
    let mut extensions: Option<&[u8]> = None;
    let mut comma_elsewhere = false;
    let mut outside_allow_list = false;
    let mut previous: &[u8] = &[];
    for (index, word) in words().enumerate() {
        let name = switch_name(word);
        if refused_switch(&name) {
            return Some(Refusal::Unverifiable);
        }
        if name == b"load-extension" {
            let value = switch_value(word);
            match extensions {
                Some(seen) if seen != value => return Some(Refusal::Unverifiable),
                Some(_) => {}
                None if system_extensions(value, trust) => extensions = Some(value),
                None => return Some(Refusal::Unverifiable),
            }
            previous = word;
            continue;
        }
        comma_elsewhere |= word.contains(&b',');
        outside_allow_list |= !beside_system_extensions(index, previous, word, &name);
        previous = word;
    }
    (extensions.is_some() && (comma_elsewhere || outside_allow_list))
        .then_some(Refusal::Unverifiable)
}

/// Why the check refuses a browser. The namespace case and a switch that turns off the
/// sandbox or site isolation have their own messages: each names a setup that the
/// owner can change, and reveals nothing about the vault.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// Anything that cannot be verified: the generic [`super::refused`].
    Unverifiable,
    /// The browser runs in another mount or user namespace than Apassy: a snap, a
    /// Flatpak, or another container or sandbox ([`super::sandboxed`]).
    OtherNamespace,
    /// The browser was started with this switch of [`WEAKENING_SWITCHES`], or with
    /// `--disable-features` naming a feature of [`WEAKENING_FEATURE_WORDS`]
    /// ([`super::weakened`]).
    Weakened(&'static str),
}

impl From<io::Error> for Refusal {
    fn from(_: io::Error) -> Self {
        Self::Unverifiable
    }
}

#[cfg(target_os = "linux")]
impl Refusal {
    fn wire(self) -> WireError {
        match self {
            Self::Unverifiable => super::refused(),
            Self::OtherNamespace => super::sandboxed(),
            Self::Weakened(switch) => super::weakened(switch),
        }
    }
}

/// A namespace that the browser must share with Apassy, as `/proc/PID/ns/` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    /// The browser read its files, `--load-extension` folders included, in its mount
    /// namespace; Apassy checks paths in its own.
    Mount,
    /// In another user namespace, the user IDs and file owners that Apassy reads are
    /// not those that the browser has.
    User,
}

const NAMESPACES: [Namespace; 2] = [Namespace::Mount, Namespace::User];

impl Namespace {
    #[cfg(target_os = "linux")]
    fn file(self) -> &'static str {
        match self {
            Self::Mount => "mnt",
            Self::User => "user",
        }
    }
}

/// Whose namespace a [`same_namespaces`] reader reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Of {
    /// The browser process with this PID.
    Browser(u32),
    /// The thread of Apassy that runs the check (its file lookups use its mount
    /// namespace).
    Apassy,
}

/// The identity of one namespace: the device and inode of its nsfs file.
type NamespaceId = (u64, u64);

/// The browser's mount and user namespaces must be Apassy's own. `read` gives the
/// identity of one namespace ([`proc_namespace`]; tests inject one). A read error
/// is a generic refusal; a different namespace is [`Refusal::OtherNamespace`].
fn same_namespaces(
    pid: u32,
    read: impl Fn(Of, Namespace) -> io::Result<NamespaceId>,
) -> Result<(), Refusal> {
    for kind in NAMESPACES {
        if read(Of::Browser(pid), kind)? != read(Of::Apassy, kind)? {
            return Err(Refusal::OtherNamespace);
        }
    }
    Ok(())
}

/// `/proc/PID/ns/KIND`, or `/proc/thread-self/ns/KIND` for Apassy. Following these
/// links needs the same ptrace read access as `/proc/PID/exe`; the PID is the one
/// that [`process`] reads before and after, so a reused PID is refused.
#[cfg(target_os = "linux")]
fn proc_namespace(of: Of, kind: Namespace) -> io::Result<NamespaceId> {
    let path = match of {
        Of::Browser(pid) => format!("/proc/{pid}/ns/{}", kind.file()),
        Of::Apassy => format!("/proc/thread-self/ns/{}", kind.file()),
    };
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// The browser parent: its user and start time, its namespaces, its executable and
/// its title, then all but the title again, so that a PID that changed hands in
/// between is refused. Returns what it saw of the browser, for [`check_same_peer`].
#[cfg(target_os = "linux")]
fn browser(pid: u32, uid: u32) -> Result<(Process, PathBuf), Refusal> {
    let before = process(pid, uid)?;
    same_namespaces(pid, proc_namespace)?;
    let path = image(pid, BROWSERS)?;
    if let Some(refusal) = title_refusal(
        &bounded(Path::new(&format!("/proc/{pid}/cmdline")))?,
        Trust::system(),
    ) {
        return Err(refusal);
    }
    same_namespaces(pid, proc_namespace)?;
    if before != process(pid, uid)? || path != image(pid, BROWSERS)? {
        return Err(Refusal::Unverifiable);
    }
    Ok((before, path))
}

#[cfg(target_os = "linux")]
fn owner_uid() -> io::Result<u32> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || rustix::process::geteuid().as_raw() != uid {
        return Err(invalid());
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
pub(super) fn check_browser_parent() -> Result<(), WireError> {
    (|| -> Result<(), Refusal> {
        let uid = owner_uid()?;
        let pid = std::process::id();
        image(pid, &[HOST])?;
        let before = process(pid, uid)?;
        browser(before.parent, uid)?;
        if before != process(pid, uid)? {
            return Err(Refusal::Unverifiable);
        }
        Ok(())
    })()
    .map_err(Refusal::wire)
}

/// What [`check_peer`] saw of the peer, all of it the kernel's data: the PID and user of
/// the socket peer (`SO_PEERCRED`), its start time, user IDs and parent (procfs), and of
/// that browser parent its start time, user IDs and executable. The app compares it
/// after the owner answered ([`check_same_peer`]).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seen {
    peer: (u32, Process),
    browser: (Process, PathBuf),
}

/// True when procfs hides `pid`'s executable because the task is not dumpable:
/// the kernel then gives the `exe` link (and the other per-process files) to root.
/// The `/proc/PID` directory itself keeps the task's effective user even then
/// (`task_dump_owner` exempts world-readable directories), so it cannot tell a
/// hardened peer from any other refusal.
#[cfg(target_os = "linux")]
fn exe_hidden_by_kernel(pid: u32) -> io::Result<bool> {
    Ok(fs::symlink_metadata(format!("/proc/{pid}/exe"))?.uid() == 0)
}

/// The app's check of the socket peer, after the request line was read and before any
/// dialog. Every property comes from the kernel: the peer's user and PID from
/// `SO_PEERCRED`; its start time, user IDs and parent from `/proc/PID/stat` and
/// `status`; its executable from `/proc/PID/exe`, or, when the kernel hides that link
/// of a non-dumpable task, only that kernel refusal; and the browser parent as in
/// [`browser`]. The peer's own process is read again after the browser, and
/// [`check_same_peer`] repeats the whole check before the answer leaves.
#[cfg(target_os = "linux")]
pub(super) fn check_peer(stream: &UnixStream) -> Result<Seen, WireError> {
    (|| -> Result<Seen, Refusal> {
        let uid = owner_uid()?;
        let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(io::Error::from)?;
        if credentials.uid.as_raw() != uid {
            return Err(Refusal::Unverifiable);
        }
        let pid = credentials.pid.as_raw_nonzero().get() as u32;
        // Hold a kernel PID handle throughout the snapshot checks. A vanished peer
        // or old kernel without pidfd support fails closed.
        let _peer =
            rustix::process::pidfd_open(credentials.pid, rustix::process::PidfdFlags::empty())
                .map_err(io::Error::from)?;
        let before = process(pid, uid)?;
        match fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(_) => {
                image(pid, &[HOST])?;
            }
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    && exe_hidden_by_kernel(pid)? => {}
            Err(error) => return Err(error.into()),
        }
        let browser = browser(before.parent, uid)?;
        if before != process(pid, uid)? {
            return Err(Refusal::Unverifiable);
        }
        Ok(Seen {
            peer: (pid, before),
            browser,
        })
    })()
    .map_err(Refusal::wire)
}

/// After the owner answered and before the answer is written: the same check again, and
/// the same peer process with the same browser parent, by PID and start time. A peer or
/// browser that ended, or a PID that changed hands while the owner looked at the dialog,
/// gets the generic refusal instead of the answer.
#[cfg(target_os = "linux")]
pub(super) fn check_same_peer(stream: &UnixStream, seen: &Seen) -> Result<(), WireError> {
    same_peer(check_peer(stream), seen)
}

/// The second check's result `now` against what the first check saw.
#[cfg(target_os = "linux")]
fn same_peer(now: Result<Seen, WireError>, seen: &Seen) -> Result<(), WireError> {
    if now? == *seen {
        Ok(())
    } else {
        Err(super::refused())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(state: &str, parent: &str, start: &str) -> String {
        format!(
            "42 (not a (browser)) {state} {parent} {} {start} 0 0",
            vec!["0"; 17].join(" ")
        )
    }

    #[test]
    fn kernel_stat_uses_fields_not_process_names_and_rejects_dead_processes() {
        assert_eq!(parse_stat(&stat("S", "7", "123")).unwrap(), (7, 123));
        for value in [
            stat("Z", "7", "123"),
            stat("X", "7", "123"),
            stat("S", "0", "123"),
            stat("S", "7", "0"),
            "42 (chrome) S 7".into(),
        ] {
            assert!(parse_stat(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn all_kernel_user_ids_must_be_present_and_unambiguous() {
        assert_eq!(
            parse_uids("Name:\tchrome\nUid:\t1000 1000 1000 1000\n").unwrap(),
            [1000; 4]
        );
        for value in [
            "Uid:\t1000 1000 1000\n",
            "Uid:\t1000 1000 1000 1000\nUid:\t0 0 0 0\n",
            "Name:\tchrome\n",
            "Uid:\tx 1 1 1\n",
        ] {
            assert!(parse_uids(value).is_err());
        }
    }

    #[test]
    fn only_root_owned_nonwritable_regular_executables_are_trusted() {
        assert!(safe_mode(0, 0o100755, true));
        assert!(!safe_mode(1000, 0o100755, true));
        assert!(!safe_mode(0, 0o100775, true));
        assert!(!safe_mode(0, 0o100757, true));
        assert!(!safe_mode(0, 0o104755, true));
        assert!(!safe_mode(0, 0o100644, true));
        assert!(
            trusted_binary(&std::env::current_exe().unwrap()).is_err(),
            "a source-build executable cannot be trusted"
        );
        assert!(
            trusted_binary(Path::new("/proc/self/exe")).is_err(),
            "a symlink cannot be an installed executable path"
        );
        assert!(trusted_binary(Path::new("target/debug/apassy-browser-host")).is_err());
        assert!(
            !BROWSERS.contains(&"/usr/bin/google-chrome"),
            "wrappers are not executable identities"
        );
    }

    #[test]
    fn unsafe_switches_fail_closed_without_disclosing_their_values() {
        assert!(safe_arguments(
            b"/opt/google/chrome/chrome\0--profile-directory=Default\0"
        ));
        for switch in [
            "--remote-debugging-port=9223",
            "-remote-debugging-pipe",
            "---REMOTE-DEBUGGING-address=secret",
            "--load-extension=/secret",
            "--disable-extensions-except=/secret",
            "--type=renderer",
        ] {
            assert!(
                !safe_arguments(format!("chrome\0--\0{switch}\0").as_bytes()),
                "{switch}"
            );
        }
        assert!(!safe_arguments(b""));
        assert!(!safe_arguments(b"chrome\0--remote-debugging-port=0"));
    }

    /// Chrome's title as the kernel shows it after the rewrite, with `switch` added.
    fn chrome(switch: &str) -> Vec<u8> {
        format!("/opt/google/chrome/chrome {switch} http://localhost:4174/passkey.html\0")
            .into_bytes()
    }

    /// Every refused switch, with and without a value, in every spelling that Chrome
    /// reads, refuses Chrome's title and the argument strings before a rewrite.
    #[test]
    fn every_refused_switch_refuses_the_browser() {
        let mut refused: Vec<String> = REFUSED_SWITCHES.iter().map(|s| s.to_string()).collect();
        refused.extend(
            WEAKENING_SWITCHES
                .iter()
                .map(|s| s.trim_start_matches('-').to_owned()),
        );
        for name in [
            "remote-debugging-port",
            "remote-debugging-pipe",
            "remote-debugging-address",
            "remote-debugging-socket-name",
            "remote-debugging-io-pipes",
            "remote-debugging-targets",
            "remote-debugging-anything-later",
        ] {
            refused.push(name.into());
        }
        // The families that the list must cover, by one name each.
        for family in [
            "load-apps",
            "enable-automation",
            "renderer-cmd-prefix",
            "browser-subprocess-path",
            "disable-web-security",
            "ignore-certificate-errors",
            "host-resolver-rules",
        ] {
            assert!(REFUSED_SWITCHES.contains(&family), "{family}");
        }
        for name in &refused {
            for word in [
                format!("--{name}"),
                format!("--{name}=1"),
                format!("--{name}=/tmp/x"),
                format!("-{name}"),
                format!("--{}", name.to_ascii_uppercase()),
            ] {
                assert!(!safe_arguments(&chrome(&word)), "{word}");
                assert!(
                    !safe_arguments(format!("chrome\0{word}\0").as_bytes()),
                    "{word}"
                );
            }
        }
    }

    /// Switches that ordinary Linux users set: for the display (Wayland, scale), the
    /// GPU, the language, the profile folder, the password store or a proxy. A
    /// false refusal would break their browser.
    const KEPT: &[&str] = &[
        "--ozone-platform=wayland",
        "--ozone-platform=x11",
        "--ozone-platform-hint=auto",
        "--enable-features=UseOzonePlatform,WaylandWindowDecorations",
        "--enable-features=WaylandWindowDecorations",
        "--enable-features=VaapiVideoDecoder,VaapiVideoEncoder",
        "--disable-features=WaylandFractionalScaleV1",
        "--disable-features=PrivacySandboxAdsAPIsOverride,Translate",
        "--enable-wayland-ime",
        "--wayland-text-input-version=3",
        "--gtk-version=4",
        "--force-device-scale-factor=1.25",
        "--force-dark-mode",
        "--start-maximized",
        "--disable-gpu",
        "--disable-gpu-compositing",
        "--enable-gpu-rasterization",
        "--ignore-gpu-blocklist",
        "--enable-zero-copy",
        "--use-gl=angle",
        "--use-angle=vulkan",
        "--lang=pl",
        "--accept-lang=pl-PL,pl,en",
        "--password-store=basic",
        "--password-store=gnome-libsecret",
        "--user-data-dir=/home/owner/.config/chrome-work",
        "--profile-directory=Profile 1",
        "--proxy-server=socks5://127.0.0.1:1080",
        "--proxy-pac-url=http://proxy.example/proxy.pac",
        "--no-proxy-server",
        "--incognito",
        "--new-window",
        "--no-first-run",
        "--disable-dev-shm-usage",
    ];

    #[test]
    fn ordinary_linux_switches_are_accepted() {
        for switch in KEPT {
            assert!(safe_arguments(&chrome(switch)), "{switch}");
        }
        // And all at once, as one rewritten title.
        assert!(safe_arguments(&chrome(&KEPT.join(" "))));
    }

    /// No kept switch is on the refused list, and the allow list next to system
    /// extensions holds no refused switch.
    #[test]
    fn the_lists_do_not_overlap() {
        for switch in KEPT {
            assert!(!refused_switch(&switch_name(switch.as_bytes())), "{switch}");
        }
        for name in DEBIAN_WRAPPER_SWITCHES.iter().chain(DISPLAY_SWITCHES) {
            assert!(!refused_switch(name.as_bytes()), "{name}");
        }
    }

    /// The switches that turn off the sandbox or site isolation refuse every browser,
    /// next to a system extension too, and the refusal names the switch, never its
    /// value.
    #[test]
    fn switches_that_weaken_the_sandbox_or_site_isolation_name_themselves() {
        let root = FakeRoot::new();
        for switch in WEAKENING_SWITCHES {
            for word in [
                switch.to_string(),
                format!("{switch}=--expose-gc"),
                format!("-{}", switch.trim_start_matches('-').to_ascii_uppercase()),
            ] {
                let want = Some(Refusal::Weakened(switch));
                let Some(Refusal::Weakened(named)) = title_refusal(&chrome(&word), Trust::system())
                else {
                    panic!("{word} is not a weakening");
                };
                assert_eq!(named, *switch);
                assert_eq!(
                    title_refusal(&chrome(&word), Trust::system()),
                    want,
                    "{word}"
                );
                assert_eq!(
                    title_refusal(
                        format!("{DEBIAN} --load-extension={A} {word}\0").as_bytes(),
                        root.trust()
                    ),
                    want,
                    "{word}"
                );
            }
        }
        for value in [
            "IsolateOrigins",
            "OriginIsolationHeader",
            "StrictOriginIsolation",
            "OriginKeyedProcessesByDefault",
            "SiteIsolationForCrossOriginOpenerPolicy",
            "site-isolation-for-password-sites",
            "SiteIsolationForOAuthSites<Trial",
            "IsolateOriginsShortlistPolicyUpdate:a/b",
            "*NetworkServiceSandbox",
            "AudioServiceSandbox",
            "SpareRendererForSitePerProcess",
            "WaylandWindowDecorations,IsolateOrigins",
            "isolateorigins",
        ] {
            let word = format!("--disable-features={value}");
            assert_eq!(
                title_refusal(&chrome(&word), Trust::system()),
                Some(Refusal::Weakened("--disable-features")),
                "{word}"
            );
        }
        for value in [
            "WaylandFractionalScaleV1",
            "PrivacySandboxAdsAPIsOverride",
            "Translate,MediaRouter",
            "",
        ] {
            assert!(!weakening_features(value.as_bytes()), "{value}");
        }
        // `--enable-features` with the same names is not a weakening.
        assert!(safe_arguments(&chrome("--enable-features=IsolateOrigins")));
        // The message names the switch and what to do, and differs from the
        // generic refusal.
        let error = super::super::weakened("--no-sandbox");
        assert_eq!(error.code, "unsupported");
        assert_ne!(error.message, super::super::refused().message);
        assert_eq!(error.message.matches("--no-sandbox").count(), 2);
        assert!(
            error
                .message
                .ends_with("Start the browser again without --no-sandbox.")
        );
        assert!(!error.message.contains("expose"));
    }

    /// Chrome 157 on Ubuntu 24.04, started with `--remote-debugging-port=9333`, showed
    /// this exact `/proc/PID/cmdline`: one string after its process-title rewrite.
    #[test]
    fn rewritten_browser_titles_are_checked_word_by_word() {
        assert!(safe_arguments(b"/opt/google/chrome/chrome\0"));
        assert!(safe_arguments(
            b"/opt/google/chrome/chrome --profile-directory=Default http://localhost:4174/\0"
        ));
        for title in [
            &b"/opt/google/chrome/chrome --remote-debugging-port=9333 http://localhost:4174/passkey.html\0"[..],
            b"/usr/lib/chromium/chromium --show-component-extension-options --load-extension=/tmp/x\0",
            b"/opt/google/chrome/chrome\t--disable-extensions-except=/tmp/x\0",
            b"/opt/google/chrome/chrome --type=utility --utility-sub-type=x\0",
            b"--remote-debugging-pipe\0",
        ] {
            assert!(!safe_arguments(title), "{}", String::from_utf8_lossy(title));
        }
    }

    /// A private stand-in for `/`: `usr/share/chromium/extensions` with the
    /// extensions `a` and `b`, and a folder `home/user/evil` outside it. Every folder
    /// is the test user's and mode 0755; the root is 0700. The trusted owner is the
    /// test user, because a test cannot make root-owned files.
    struct FakeRoot {
        dir: TestDir,
        owner: u32,
    }

    /// A new private folder in the temporary folder, removed on drop. (`tempfile` is a
    /// dependency of the vault feature only, and this module builds without it.)
    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "apassy-caller-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl FakeRoot {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = TestDir::new();
            for path in [
                "usr/share/chromium/extensions/a",
                "usr/share/chromium/extensions/b",
                "home/user/evil",
            ] {
                fs::create_dir_all(dir.path().join(path)).unwrap();
            }
            for path in [
                "usr",
                "usr/share",
                "usr/share/chromium",
                "usr/share/chromium/extensions",
                "usr/share/chromium/extensions/a",
                "usr/share/chromium/extensions/b",
                "home",
                "home/user",
                "home/user/evil",
            ] {
                fs::set_permissions(dir.path().join(path), fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let owner = fs::metadata(dir.path()).unwrap().uid();
            Self { dir, owner }
        }

        fn trust(&self) -> Trust<'_> {
            Trust {
                root: self.dir.path(),
                owner: self.owner,
            }
        }

        fn path(&self, relative: &str) -> std::path::PathBuf {
            self.dir.path().join(relative)
        }

        fn chmod(&self, relative: &str, mode: u32) {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.path(relative), fs::Permissions::from_mode(mode)).unwrap();
        }

        fn accepts(&self, title: &str) -> bool {
            safe_arguments_in(format!("{title}\0").as_bytes(), self.trust())
        }
    }

    const A: &str = "/usr/share/chromium/extensions/a";
    const B: &str = "/usr/share/chromium/extensions/b";
    /// The start of the process title of Debian 13's Chromium 156 after its wrapper
    /// (`/usr/bin/chromium`) and `/etc/chromium.d/*` added their switches.
    const DEBIAN: &str = "/usr/lib/chromium/chromium --show-component-extension-options --enable-gpu-rasterization --no-default-browser-check --disable-pings --media-router=0 --enable-remote-extensions";

    #[test]
    fn system_extensions_of_the_distribution_are_accepted() {
        let root = FakeRoot::new();
        assert!(root.accepts(&format!("{DEBIAN} --load-extension={A}")));
        assert!(root.accepts(&format!("{DEBIAN} --load-extension={A},{B}")));
        // The same switch twice with the same value, and argument strings as the
        // kernel shows them before a title rewrite.
        assert!(root.accepts(&format!(
            "{DEBIAN} --load-extension={A},{B} --load-extension={A},{B}"
        )));
        assert!(safe_arguments_in(
            format!("/usr/lib/chromium/chromium\0--load-extension={A}\0http://localhost:4174/\0")
                .as_bytes(),
            root.trust()
        ));
        // A symlink in the folder that resolves to another extension in it.
        std::os::unix::fs::symlink(
            root.path(&A[1..]),
            root.path("usr/share/chromium/extensions/c"),
        )
        .unwrap();
        assert!(root.accepts(&format!(
            "{DEBIAN} --load-extension=/usr/share/chromium/extensions/c"
        )));
        // Without the switch a comma in a URL is harmless.
        assert!(root.accepts(&format!("{DEBIAN} http://localhost:4174/?a,b")));
    }

    #[test]
    fn every_other_extension_value_is_refused() {
        let root = FakeRoot::new();
        fs::write(root.path("usr/share/chromium/extensions/file"), b"").unwrap();
        std::os::unix::fs::symlink(
            root.path("home/user/evil"),
            root.path("usr/share/chromium/extensions/link-out"),
        )
        .unwrap();
        for value in [
            // Empty: Debian's default without system extensions.
            "--load-extension=".to_owned(),
            "--load-extension".to_owned(),
            // Elsewhere, relative, missing, a file, the folder itself.
            "--load-extension=/home/user/evil".to_owned(),
            format!("--load-extension={A},/home/user/evil"),
            "--load-extension=usr/share/chromium/extensions/a".to_owned(),
            "--load-extension=./a".to_owned(),
            "--load-extension=/usr/share/chromium/extensions/missing".to_owned(),
            "--load-extension=/usr/share/chromium/extensions/file".to_owned(),
            "--load-extension=/usr/share/chromium/extensions".to_owned(),
            "--load-extension=/usr/share/chromium/extensions/".to_owned(),
            "--load-extension=/usr/share/chromium/extensions/../../../../home/user/evil".to_owned(),
            "--load-extension=/usr/share/chromium/extensions/link-out".to_owned(),
            "--load-extension=/usr/share/chromium/extensions-x".to_owned(),
            "--load-extension=//home/user/evil".to_owned(),
            // Empty items.
            format!("--load-extension={A},"),
            format!("--load-extension=,{A}"),
            format!("--load-extension={A},,{B}"),
            // A second switch with another value, in either order.
            format!("--load-extension={A} --load-extension={B}"),
            format!("--load-extension={A},{B} --load-extension={A}"),
            format!("--load-extension={A} --load-extension=/home/user/evil"),
            // A value with a space can go on into the next words: Chrome would load
            // `/home/user/evil` as a second item.
            format!("--load-extension={A} /x,/home/user/evil"),
            format!("--load-extension={A} --x,/home/user/evil"),
            format!("http://localhost:4174/?a,b --load-extension={A}"),
            // Other unsafe switches stay refused next to a system extension.
            format!("--load-extension={A} --remote-debugging-port=9222"),
            format!("--load-extension={A} --disable-extensions-except={A}"),
            format!("--load-extension={A} --type=renderer"),
            format!("--LOAD-EXTENSION={A},/home/user/evil"),
        ] {
            assert!(!root.accepts(&format!("{DEBIAN} {value}")), "{value}");
        }
    }

    /// The exact process titles of Debian 13's Chromium 156 in the second Linux
    /// acceptance run (2026-11-10): with the Debian package `chromium-lwn4chrome`
    /// (accepted), without any system extension (the wrapper's empty value, which the
    /// title shows without `=`), and with the owner's own extension folder added.
    #[test]
    fn observed_debian_13_titles() {
        let root = FakeRoot::new();
        fs::create_dir_all(root.path("usr/share/chromium/extensions/lwn4chrome")).unwrap();
        root.chmod("usr/share/chromium/extensions/lwn4chrome", 0o755);
        const START: &str = "/usr/lib/chromium/chromium --show-component-extension-options --enable-gpu-rasterization --no-default-browser-check --disable-pings --media-router=0 --disable-dev-shm-usage --enable-remote-extensions";
        assert!(root.accepts(&format!(
            "{START} --load-extension=/usr/share/chromium/extensions/lwn4chrome http://localhost:4174/passkey.html"
        )));
        assert!(!root.accepts(&format!("{START} --load-extension")));
        assert!(!root.accepts(&format!(
            "{START} --load-extension=/usr/share/chromium/extensions/lwn4chrome --load-extension=/home/l5owner/l5-user-ext http://localhost:4174/passkey.html"
        )));
    }

    /// Next to Debian's system extensions only the wrapper's own switches, display,
    /// GPU and language switches and page addresses may appear.
    #[test]
    fn system_extensions_allow_only_the_wrapper_and_display_switches() {
        let root = FakeRoot::new();
        let with = |extra: &str| root.accepts(&format!("{DEBIAN} --load-extension={A} {extra}"));
        // Everything that Debian's wrapper and /etc/chromium.d add.
        assert!(root.accepts(&format!(
            "{DEBIAN} --disable-dev-shm-usage --disable-background-networking --load-extension={A}"
        )));
        for allowed in [
            "",
            "http://localhost:4174/passkey.html",
            "HTTPS://example.org/",
            "--ozone-platform=wayland",
            "--ozone-platform-hint=auto",
            "--force-device-scale-factor=1.25",
            "--enable-features=WaylandWindowDecorations",
            "--disable-features=WaylandFractionalScaleV1",
            "--use-gl=angle",
            "--disable-gpu",
            "--lang=pl",
            "--enable-wayland-ime --gtk-version=4 https://example.org/",
            // The profile, password store and proxy (decided 2026-11-11): Chromium's
            // per-profile desktop shortcuts start it with `--profile-directory`.
            "--profile-directory=Default",
            "--profile-directory=Profile 1",
            "--profile-directory=Profile 12 http://localhost:4174/",
            "--user-data-dir=/home/owner/x",
            "--password-store=basic",
            "--password-store=gnome-libsecret",
            "--proxy-server=socks5://127.0.0.1:1080",
            "--proxy-server=http://proxy.example:3128 --profile-directory=Default",
        ] {
            assert!(with(allowed), "{allowed}");
        }
        for refused in [
            // Kept everywhere else, but not in the allow list.
            "--incognito",
            "--proxy-pac-url=http://proxy.example/proxy.pac",
            "--no-sandbox",
            "--single-process",
            "--js-flags=--expose-gc",
            // A number only after `--profile-directory=Profile`, and only one.
            "1",
            "--profile-directory=Profile x",
            "--profile-directory=Profile 1 2",
            "--profile-directory=Work 1",
            "--user-data-dir=/home/owner/x 1",
            // A comma in a profile value: Chrome would split the extension value.
            "--user-data-dir=/home/owner/a,/home/owner/evil",
            "--some-future-switch",
            "--",
            "-",
            // Features that are not about the display or the GPU, and feature
            // syntax beyond a plain name.
            "--enable-features=SomethingElse",
            "--enable-features=",
            "--enable-features=WaylandWindowDecorations<Trial",
            "--enable-features=WaylandWindowDecorations:x/y",
            "--disable-features=SitePerProcess",
            // A comma: Chrome would split a `--load-extension` value there.
            "--enable-features=UseOzonePlatform,WaylandWindowDecorations",
            "--accept-lang=pl,en",
            // Words that are no page address.
            "/home/user/evil",
            "localhost:4174",
            "file:///home/user/x.html",
            "chrome://extensions",
            "javascript:alert(1)",
        ] {
            assert!(!with(refused), "{refused}");
        }
        // The first word must be the browser executable.
        assert!(!root.accepts(&format!("chromium --load-extension={A}")));
        assert!(!root.accepts(&format!(
            "/tmp/chromium --show-component-extension-options --load-extension={A}"
        )));
        assert!(!root.accepts(&format!("http://localhost:4174/ --load-extension={A}")));
        // Order does not matter: a switch before the extension refuses too.
        assert!(!root.accepts(&format!(
            "/usr/lib/chromium/chromium --incognito --load-extension={A}"
        )));
        // The profile switch of a Chromium desktop shortcut, before the extension.
        assert!(root.accepts(&format!(
            "{DEBIAN} --profile-directory=Default --load-extension={A} http://localhost:4174/"
        )));
        // The same title without the system extension is accepted: the allow list
        // applies only with an accepted `--load-extension`.
        assert!(root.accepts(&format!(
            "{DEBIAN} --password-store=basic --user-data-dir=/home/owner/x"
        )));
    }

    #[test]
    fn display_features_are_plain_names_with_a_display_word() {
        for value in [
            "WaylandWindowDecorations",
            "UseOzonePlatform",
            "VaapiVideoDecodeLinuxGL",
            "Vulkan",
            "AcceleratedVideoDecodeLinuxZeroCopyGL",
            "UseOzonePlatform,WaylandWindowDecorations",
        ] {
            assert!(display_features(value.as_bytes()), "{value}");
        }
        for value in [
            "",
            ",",
            "Wayland,",
            "wayland",
            "Wayland-X",
            "Wayland<Group",
            "Wayland:a/b",
            "Wayland*",
            "SitePerProcess",
        ] {
            assert!(!display_features(value.as_bytes()), "{value}");
        }
    }

    /// Namespace identities of a test: Apassy's are `(1, 10)` and `(1, 20)`.
    fn namespaces_of(browser: [io::Result<NamespaceId>; 2]) -> Result<(), Refusal> {
        let browser = std::cell::RefCell::new(browser.map(Some));
        same_namespaces(7, |of, kind| {
            let index = NAMESPACES.iter().position(|k| *k == kind).unwrap();
            match of {
                Of::Browser(pid) => {
                    assert_eq!(pid, 7);
                    browser.borrow_mut()[index].take().unwrap()
                }
                Of::Apassy => Ok((1, [10, 20][index])),
            }
        })
    }

    #[test]
    fn the_browser_must_share_the_mount_and_user_namespace_of_apassy() {
        assert_eq!(namespaces_of([Ok((1, 10)), Ok((1, 20))]), Ok(()));
        for (browser, want) in [
            // Another mount namespace: a snap, a Flatpak, a container, firejail.
            ([Ok((1, 11)), Ok((1, 20))], Refusal::OtherNamespace),
            // Another user namespace: `unshare -U`, bubblewrap.
            ([Ok((1, 10)), Ok((1, 21))], Refusal::OtherNamespace),
            // The same inode on another device is another namespace.
            ([Ok((2, 10)), Ok((1, 20))], Refusal::OtherNamespace),
            // Unreadable: a generic refusal, never a pass.
            ([Err(invalid()), Ok((1, 20))], Refusal::Unverifiable),
            (
                [Ok((1, 10)), Err(io::ErrorKind::PermissionDenied.into())],
                Refusal::Unverifiable,
            ),
        ] {
            assert_eq!(namespaces_of(browser), Err(want));
        }
        // Apassy's own namespaces unreadable: refused too.
        assert_eq!(
            same_namespaces(7, |of, _| match of {
                Of::Browser(_) => Ok((1, 10)),
                Of::Apassy => Err(invalid()),
            }),
            Err(Refusal::Unverifiable)
        );
    }

    /// The refusal of a sandboxed browser is "not supported" and gives the same
    /// explanation as the "Not supported" state of a snap or Flatpak.
    #[test]
    fn a_sandboxed_browser_is_not_supported_with_the_snap_and_flatpak_explanation() {
        use super::super::super::install::{
            SANDBOX_REASON, UNSUPPORTED_ALTERNATIVE, Unsupported, find,
        };
        let error = super::super::sandboxed();
        assert_eq!(error.code, "unsupported");
        assert_ne!(error.message, super::super::refused().message);
        assert!(error.message.contains(SANDBOX_REASON), "{}", error.message);
        assert!(error.message.ends_with(UNSUPPORTED_ALTERNATIVE));
        let chromium = find("chromium").unwrap();
        for kind in [Unsupported::Snap, Unsupported::Flatpak] {
            assert!(kind.explain(chromium).contains(SANDBOX_REASON));
        }
        assert!(
            !Unsupported::UnknownBuild
                .explain(chromium)
                .contains(SANDBOX_REASON)
        );
    }

    /// The real reader: this process and a child of it share their namespaces.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_real_namespaces_of_a_child_are_apassys() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert_eq!(same_namespaces(child.id(), proc_namespace), Ok(()));
        assert_eq!(same_namespaces(std::process::id(), proc_namespace), Ok(()));
        for kind in NAMESPACES {
            assert_eq!(
                proc_namespace(Of::Browser(child.id()), kind).unwrap(),
                proc_namespace(Of::Apassy, kind).unwrap()
            );
        }
        // A process that is gone has no namespaces: a generic refusal.
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            same_namespaces(child.id(), proc_namespace),
            Err(Refusal::Unverifiable)
        );
    }

    #[test]
    fn system_extensions_need_trusted_unwritable_folders_up_to_the_root() {
        let root = FakeRoot::new();
        let title = format!("{DEBIAN} --load-extension={A}");
        assert!(root.accepts(&title));
        for (path, mode) in [
            (&A[1..], 0o775),
            (&A[1..], 0o757),
            ("usr/share/chromium/extensions", 0o775),
            ("usr/share/chromium", 0o757),
            ("usr/share", 0o775),
            ("usr", 0o777),
            ("", 0o770),
        ] {
            root.chmod(path, mode);
            assert!(!root.accepts(&title), "{path} {mode:o}");
            root.chmod(path, if path.is_empty() { 0o700 } else { 0o755 });
            assert!(root.accepts(&title), "{path} restored");
        }
        // Another owner than the trusted one.
        let other = Trust {
            root: root.dir.path(),
            owner: root.owner.wrapping_add(1),
        };
        assert!(!safe_arguments_in(format!("{title}\0").as_bytes(), other));
        // No extension folder at all.
        fs::remove_dir_all(root.path("usr/share/chromium")).unwrap();
        assert!(!root.accepts(&title));
    }

    #[test]
    fn the_system_root_refuses_paths_outside_the_system_extension_folder() {
        for title in [
            &b"/usr/lib/chromium/chromium --load-extension=/tmp\0"[..],
            b"/usr/lib/chromium/chromium --load-extension=\0",
            b"/usr/lib/chromium/chromium --load-extension=/usr/share/chromium/extensions/../../../../tmp\0",
        ] {
            assert!(!safe_arguments(title), "{}", String::from_utf8_lossy(title));
        }
    }

    /// Set by [`hidden_exe_of_a_non_dumpable_peer_is_recognized`] for its child.
    #[cfg(target_os = "linux")]
    const NON_DUMPABLE_CHILD: &str = "APASSY_TEST_NON_DUMPABLE_CHILD";

    /// Child mode of the test below: become non-dumpable, as the hardened host does,
    /// and wait until the parent closes standard input. A no-op in a normal run.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_dumpable_child_process() {
        if std::env::var_os(NON_DUMPABLE_CHILD).is_none() {
            return;
        }
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .unwrap();
        let mut rest = Vec::new();
        let _ = io::stdin().read_to_end(&mut rest);
    }

    /// The real hardened host is non-dumpable. The app must still recognize the kernel
    /// refusal for it: the `/proc/PID` directory keeps the user of the task, only the
    /// files in it become root's (found in the Linux acceptance, 2026-11-10).
    #[cfg(target_os = "linux")]
    #[test]
    fn hidden_exe_of_a_non_dumpable_peer_is_recognized() {
        use std::process::{Command, Stdio};
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser::caller::linux::tests::non_dumpable_child_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(NON_DUMPABLE_CHILD, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !exe_hidden_by_kernel(pid).unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "the child stayed dumpable"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let error = fs::read_link(format!("/proc/{pid}/exe")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::metadata(format!("/proc/{pid}")).unwrap().uid(),
            rustix::process::getuid().as_raw(),
            "the directory owner does not reveal a non-dumpable task"
        );
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        // A dumpable process of the same user shows its executable.
        let mut plain = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        assert!(!exe_hidden_by_kernel(plain.id()).unwrap());
        plain.kill().unwrap();
        plain.wait().unwrap();
    }

    /// The check after the owner answered passes only for the same peer process and
    /// the same browser parent, by PID and start time; a failed second check refuses.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_answer_needs_the_same_peer_and_browser_after_the_owner_answered() {
        let process = |parent, start| Process {
            parent,
            start,
            uids: [1000; 4],
        };
        let seen = Seen {
            peer: (42, process(7, 100)),
            browser: (process(1, 50), PathBuf::from("/opt/google/chrome/chrome")),
        };
        assert!(same_peer(Ok(seen.clone()), &seen).is_ok());
        let mut changed = Vec::new();
        // The PID changed hands: another process with the same number.
        let mut other = seen.clone();
        other.peer.1.start = 101;
        changed.push(other);
        // Another peer PID.
        let mut other = seen.clone();
        other.peer.0 = 43;
        changed.push(other);
        // The browser parent was replaced.
        let mut other = seen.clone();
        other.browser.0.start = 51;
        changed.push(other);
        let mut other = seen.clone();
        other.browser.1 = PathBuf::from("/usr/lib/chromium/chromium");
        changed.push(other);
        for now in changed {
            let error = same_peer(Ok(now), &seen).unwrap_err();
            assert_eq!(error, super::super::refused());
        }
        // The second check itself refuses: its refusal is the answer.
        let error = same_peer(Err(super::super::sandboxed()), &seen).unwrap_err();
        assert_eq!(error, super::super::sandboxed());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_kernel_peer_credentials_cannot_turn_a_test_process_into_a_browser_host() {
        let (one, _two) = UnixStream::pair().unwrap();
        let credentials = rustix::net::sockopt::socket_peercred(&one).unwrap();
        assert_eq!(
            credentials.pid.as_raw_nonzero().get() as u32,
            std::process::id()
        );
        assert_eq!(check_peer(&one).unwrap_err().code, "unsupported");
        assert_eq!(check_browser_parent().unwrap_err().code, "unsupported");
    }
}
