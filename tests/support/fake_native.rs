//! A fake native helper for tests (goal items A2 to A4, N1 to N4).
//!
//! The fake is a shell script. It logs each request line and answers with the file
//! `response.<cmd>` for the command of the request, or with no line. So one fake can
//! answer `keychain_exists`, `keychain_read`, and `notify` in different ways. All data
//! is synthetic.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use apassy::native::NativeHelper;
use serde_json::Value;

const SCRIPT: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
IFS= read -r line
printf '%s\n' "$line" >> "$dir/requests.log"
cmd=$(printf '%s' "$line" | sed -n 's/.*"cmd":"\([a-z_]*\)".*/\1/p')
if [ -f "$dir/response.$cmd" ]; then cat "$dir/response.$cmd"; fi
"#;

/// The notification status fields of an allowed channel.
pub const ALLOWED_STATUS: &str = r#""authorization":"authorized","alert":"enabled","alert_style":"banner","notification_center":"enabled","lock_screen":"enabled","sound":"enabled""#;

pub struct FakeNative {
    dir: PathBuf,
}

impl FakeNative {
    pub fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "fake-native-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create fake dir");
        let script = dir.join("helper");
        fs::write(&script, SCRIPT).expect("write fake helper");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    /// A client that uses the fake for both helpers.
    pub fn helper(&self) -> NativeHelper {
        let path = self.dir.join("helper");
        NativeHelper::with_paths(&path, &path)
    }

    /// Answer `cmd` with `line`.
    pub fn respond(&self, cmd: &str, line: &str) {
        fs::write(
            self.dir.join(format!("response.{cmd}")),
            format!("{line}\n"),
        )
        .expect("write response");
    }

    /// Answer `cmd` with a helper error.
    pub fn fail(&self, cmd: &str, code: &str) {
        self.respond(
            cmd,
            &format!(r#"{{"ok":false,"error":"{code}","message":"synthetic message"}}"#),
        );
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("requests.log")) {
            Ok(text) => text
                .lines()
                .map(|line| serde_json::from_str(line).expect("request is JSON"))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The raw request lines, for a check that a text is absent.
    pub fn raw_requests(&self) -> String {
        fs::read_to_string(self.dir.join("requests.log")).unwrap_or_default()
    }

    /// The requests with this command.
    pub fn requests_for(&self, cmd: &str) -> Vec<Value> {
        self.requests()
            .into_iter()
            .filter(|request| request["cmd"] == cmd)
            .collect()
    }
}

impl Drop for FakeNative {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Standard base64 with padding, for synthetic keychain values.
pub fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(TABLE[((n >> shift) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn base64_vectors() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
}
