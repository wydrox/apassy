//! `apassy owner serve` as a program (ADR 0045), on Linux: it refuses without a
//! terminal, refuses a second owner process, does not echo the passphrase, and ends on
//! SIGTERM without leaving a service or the owner lock behind. The terminal is a
//! pseudo-terminal that `setsid --ctty` makes the controlling terminal of the program.
//! A synthetic vault in a temporary data directory; CI builds the program with
//! `apassy/insecure-test-kdf`.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::owner::serve::instance::OwnerInstance;
use apassy::vault::Vault;

const PASSPHRASE: &str = "synthetic-serve-passphrase";

fn program() -> &'static str {
    env!("CARGO_BIN_EXE_apassy-app")
}

struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("apsv")
            .tempdir_in("/tmp")
            .unwrap();
        let root = dir.path().to_path_buf();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut vault = Vault::create(&root.join("vault.db"), PASSPHRASE).unwrap();
        vault.lock().unwrap();
        Self { _dir: dir, root }
    }

    fn vault(&self) -> PathBuf {
        self.root.join("vault.db")
    }

    /// `$XDG_DATA_HOME/apassy`, the data directory of the program.
    fn data(&self) -> PathBuf {
        self.root.join("xdg").join("apassy")
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("XDG_DATA_HOME", self.root.join("xdg"));
        command
    }
}

/// The controller side of a pseudo-terminal, and everything the program wrote to it.
struct Terminal {
    controller: File,
    output: Arc<Mutex<Vec<u8>>>,
}

impl Terminal {
    /// Start `apassy owner serve VAULT` with a new session whose controlling terminal
    /// is a new pseudo-terminal.
    fn start(home: &Home) -> (Self, Child) {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&controller).unwrap();
        unlockpt(&controller).unwrap();
        let name = ptsname(&controller, Vec::new()).unwrap();
        let path = PathBuf::from(name.into_string().unwrap());
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap()
        };
        let child = home
            .command("setsid")
            .arg("--ctty")
            .arg(program())
            .args(["owner", "serve"])
            .arg(home.vault())
            .stdin(Stdio::from(open()))
            .stdout(Stdio::from(open()))
            .stderr(Stdio::from(open()))
            .spawn()
            .unwrap();
        let controller = File::from(controller);
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut reader = controller.try_clone().unwrap();
        let sink = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    return;
                }
                sink.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });
        (Self { controller, output }, child)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    fn wait_for(&self, text: &str) {
        let started = Instant::now();
        while !self.text().contains(text) {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "never shown: {text}\n{}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn type_line(&mut self, line: &str) {
        self.controller
            .write_all(format!("{line}\n").as_bytes())
            .unwrap();
        self.controller.flush().unwrap();
    }
}

fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the program did not end"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Without a terminal on stdin (a pipe, `/dev/null`, a service manager) the program
/// refuses before it opens the vault: no approval can come from such input.
#[test]
fn serve_refuses_without_a_terminal() {
    let home = Home::new();
    for stdin in [Stdio::null(), Stdio::piped()] {
        let output = home
            .command(program())
            .args(["owner", "serve"])
            .arg(home.vault())
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("interactive terminal"), "{stderr}");
        assert!(!home.data().join("browser.sock").exists());
    }
}

/// The passphrase is typed without echo, the service answers on the browser socket,
/// and SIGTERM ends it: nothing answers any more, the owner lock is free, and the
/// vault file is locked at rest.
#[test]
fn sigterm_ends_the_service_and_frees_the_lock() {
    let home = Home::new();
    let (mut terminal, mut child) = Terminal::start(&home);
    terminal.wait_for("Vault passphrase: ");
    terminal.type_line(PASSPHRASE);
    terminal.wait_for("Vault unlocked.");
    assert!(
        !terminal.text().contains(PASSPHRASE),
        "the passphrase was echoed"
    );
    let socket = home.data().join("browser.sock");
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream.write_all(b"{\"v\":1,\"cmd\":\"status\"}\n").unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert!(answer.contains("\"unlocked\""), "{answer}");
    // A second owner process for the same data directory refuses.
    let (second, mut other) = Terminal::start(&home);
    let status = wait_exit(&mut other);
    assert_eq!(status.code(), Some(1), "{}", second.text());
    second.wait_for("Another Apassy owner process");

    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let status = wait_exit(&mut child);
    assert_eq!(status.signal(), Some(15), "{status:?}");
    assert!(UnixStream::connect(&socket).is_err());
    assert!(UnixStream::connect(home.data().join("broker.sock")).is_err());
    assert!(OwnerInstance::acquire(&home.data()).is_ok());
    assert!(Vault::open(&home.vault()).unwrap().is_locked());
}

/// `quit` locks the vault and ends the service cleanly; the socket files are gone.
#[test]
fn quit_locks_and_removes_the_sockets() {
    let home = Home::new();
    let (mut terminal, mut child) = Terminal::start(&home);
    terminal.wait_for("Vault passphrase: ");
    terminal.type_line(PASSPHRASE);
    terminal.wait_for("apassy owner serve> ");
    terminal.type_line("quit");
    let status = wait_exit(&mut child);
    assert!(status.success(), "{}", terminal.text());
    terminal.wait_for("Vault locked on request");
    assert!(!socket_exists(&home.data().join("browser.sock")));
    assert!(!socket_exists(&home.data().join("broker.sock")));
}

fn socket_exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}
