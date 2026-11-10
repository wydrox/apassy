//! The terminal of `apassy owner serve`: what the owner reads and types.
//!
//! [`Console`] is the seam: [`TtyConsole`] is the controlling terminal, and tests drive
//! the service with a scripted console. A console never takes input from a pipe or a
//! file: [`TtyConsole::open`] refuses unless stdin and stdout are terminals, and it
//! reads and writes `/dev/tty` only. Each prompt returns after at most `wait`, so the
//! service watches its requests, the inactivity time and the lock hook between keys.
//!
//! A secret prompt turns the echo off before the prompt shows, and discards input that
//! was typed ahead of it. The echo comes back after the line, after a cancelled prompt,
//! and when the console drops. The service never writes a typed line back.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use rustix::termios::{LocalModes, OptionalActions, QueueSelector, tcflush, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

/// The longest line that the console reads: the vault limit of a field value.
const MAX_LINE_BYTES: u64 = 65_536;

/// What a prompt got.
pub enum Input {
    /// One typed line, without its newline. The buffer is erased on drop.
    Line(Zeroizing<String>),
    /// No complete line before the wait ended.
    Idle,
    /// The terminal closed (end of input, a hang-up, or a read error).
    Closed,
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Line(_) => f.write_str("Input::Line([redacted])"),
            Self::Idle => f.write_str("Input::Idle"),
            Self::Closed => f.write_str("Input::Closed"),
        }
    }
}

/// The owner's terminal.
pub trait Console {
    /// Show a text to the owner. The service cleans names from a page or an agent
    /// before it shows them.
    fn show(&mut self, text: &str);
    /// Ask for a line with the echo on. Returns after at most `wait`.
    fn ask(&mut self, prompt: &str, wait: Duration) -> Input;
    /// Ask for a secret line with the echo off. Returns after at most `wait`.
    fn ask_secret(&mut self, prompt: &str, wait: Duration) -> Input;
    /// The question of the last prompt ended without an answer (for example the browser
    /// hung up): forget what was typed for it.
    fn discard_typed(&mut self) {}
}

/// The controlling terminal.
pub struct TtyConsole {
    tty: File,
    lines: Receiver<Input>,
    /// The prompt on the screen now, and whether it is a secret prompt.
    shown: Option<(String, bool)>,
    /// The terminal settings to restore while the echo is off.
    saved: Option<rustix::termios::Termios>,
    /// The reader saw the end of the terminal while a question was discarded.
    closed: bool,
}

impl TtyConsole {
    /// Open the controlling terminal. Refuses when stdin or stdout is not a terminal:
    /// a pipe, `/dev/null`, a file, or a service manager never answers an approval.
    pub fn open() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::other(
                "apassy owner serve needs an interactive terminal on stdin and stdout; redirected or non-interactive input is refused, so no approval can come from it. Run it in a terminal, tmux or screen.",
            ));
        }
        let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        if !tty.is_terminal() {
            return Err(io::Error::other("/dev/tty is not a terminal"));
        }
        let reader = tty.try_clone()?;
        let (sender, lines) = mpsc::channel();
        std::thread::Builder::new()
            .name("apassy-owner-tty".to_owned())
            .spawn(move || {
                let mut reader = BufReader::new(reader);
                loop {
                    let input = read_line(&mut reader);
                    let closed = matches!(input, Input::Closed);
                    if sender.send(input).is_err() || closed {
                        return;
                    }
                }
            })?;
        Ok(Self {
            tty,
            lines,
            shown: None,
            saved: None,
            closed: false,
        })
    }

    fn write(&mut self, text: &str) {
        let _ = self.tty.write_all(text.as_bytes());
        let _ = self.tty.flush();
    }

    fn echo_off(&mut self) {
        if self.saved.is_some() {
            return;
        }
        if let Ok(saved) = tcgetattr(&self.tty) {
            let mut quiet = saved.clone();
            quiet.local_modes.remove(LocalModes::ECHO);
            // `Flush` also discards input that was typed before the prompt.
            if tcsetattr(&self.tty, OptionalActions::Flush, &quiet).is_ok() {
                self.saved = Some(saved);
            }
        }
    }

    fn echo_on(&mut self) {
        if let Some(saved) = self.saved.take() {
            let _ = tcsetattr(&self.tty, OptionalActions::Now, &saved);
        }
    }

    fn prompt(&mut self, prompt: &str, secret: bool, wait: Duration) -> Input {
        if self.closed {
            return Input::Closed;
        }
        let wanted = (prompt.to_owned(), secret);
        if self.shown.as_ref() != Some(&wanted) {
            if self.shown.is_some() {
                self.write("\n");
            }
            if secret {
                self.echo_off();
            } else {
                self.echo_on();
            }
            self.write(prompt);
            self.shown = Some(wanted);
        }
        let input = match self.lines.recv_timeout(wait) {
            Ok(input) => input,
            Err(RecvTimeoutError::Timeout) => return Input::Idle,
            Err(RecvTimeoutError::Disconnected) => Input::Closed,
        };
        self.shown = None;
        if secret {
            self.echo_on();
            self.write("\n");
        }
        input
    }
}

fn read_line(reader: &mut BufReader<File>) -> Input {
    let mut bytes = Zeroizing::new(Vec::with_capacity(256));
    match reader
        .by_ref()
        .take(MAX_LINE_BYTES + 2)
        .read_until(b'\n', &mut bytes)
    {
        Ok(0) | Err(_) => return Input::Closed,
        Ok(_) => {}
    }
    if bytes.last() != Some(&b'\n') {
        // Too long, or the terminal closed in the middle of the line.
        return if bytes.len() as u64 > MAX_LINE_BYTES {
            Input::Line(Zeroizing::new(String::new()))
        } else {
            Input::Closed
        };
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) => Input::Line(Zeroizing::new(text.to_owned())),
        Err(_) => Input::Line(Zeroizing::new(String::new())),
    }
}

impl Console for TtyConsole {
    fn show(&mut self, text: &str) {
        if self.shown.take().is_some() {
            self.write("\n");
        }
        self.write(text);
        self.write("\n");
    }

    fn ask(&mut self, prompt: &str, wait: Duration) -> Input {
        self.prompt(prompt, false, wait)
    }

    fn ask_secret(&mut self, prompt: &str, wait: Duration) -> Input {
        self.prompt(prompt, true, wait)
    }

    fn discard_typed(&mut self) {
        let _ = tcflush(&self.tty, QueueSelector::IFlush);
        // Lines that the reader took already belong to the question that ended.
        while let Ok(input) = self.lines.try_recv() {
            if matches!(input, Input::Closed) {
                self.closed = true;
            }
        }
        self.echo_on();
        if self.shown.take().is_some() {
            self.write("\n");
        }
    }
}

impl Drop for TtyConsole {
    fn drop(&mut self) {
        self.echo_on();
    }
}
