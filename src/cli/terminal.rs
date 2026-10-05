//! Terminal input for the command line: hidden prompts, secrets from stdin, and
//! confirmations. A secret never comes from a program argument, because other local
//! processes can read process arguments.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};

use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
use zeroize::{Zeroize, Zeroizing};

use crate::owner::wire::SecretText;

/// The largest secret that the command line reads: the vault limit of a field value.
const MAX_SECRET_BYTES: u64 = 65_536;

/// True when stdin is a terminal.
pub fn stdin_is_terminal() -> bool {
    io::stdin().is_terminal()
}

/// True when stdout is a terminal.
pub fn stdout_is_terminal() -> bool {
    io::stdout().is_terminal()
}

fn open_tty() -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open("/dev/tty")
}

/// Ask on the terminal with the echo off. The prompt and the input use `/dev/tty`, so
/// a redirect of stdout or stdin does not change them.
pub fn read_hidden(prompt: &str) -> io::Result<SecretText> {
    let mut tty = open_tty().map_err(|_| {
        io::Error::other("there is no terminal for a hidden prompt. Pipe the value on stdin.")
    })?;
    let saved = tcgetattr(&tty)?;
    let mut quiet = saved.clone();
    quiet.local_modes.remove(LocalModes::ECHO);
    tcsetattr(&tty, OptionalActions::Flush, &quiet)?;
    let result = (|| {
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;
        read_line(&tty)
    })();
    // Turn the echo on again, also after a read error.
    let restore = tcsetattr(&tty, OptionalActions::Flush, &saved);
    let _ = tty.write_all(b"\n");
    let line = result?;
    restore?;
    Ok(line)
}

fn read_line(source: impl Read) -> io::Result<SecretText> {
    let mut reader = BufReader::new(source.take(MAX_SECRET_BYTES + 2));
    let mut bytes = Zeroizing::new(Vec::with_capacity(256));
    reader.read_until(b'\n', &mut bytes)?;
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    to_secret(bytes)
}

fn to_secret(mut bytes: Zeroizing<Vec<u8>>) -> io::Result<SecretText> {
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        return Err(io::Error::other("the value is larger than 64 KiB"));
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(SecretText::new(text)),
        Err(err) => {
            let mut raw = err.into_bytes();
            raw.zeroize();
            Err(io::Error::other("the value is not UTF-8 text"))
        }
    }
}

/// Ask for a secret two times on the terminal. Both must match.
pub fn read_hidden_twice(prompt: &str, again: &str) -> io::Result<SecretText> {
    let first = read_hidden(prompt)?;
    let second = read_hidden(again)?;
    if first != second {
        return Err(io::Error::other("the two values are not the same"));
    }
    Ok(first)
}

/// Read all of stdin as one secret. One final newline is removed.
pub fn read_stdin_secret() -> io::Result<SecretText> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    io::stdin()
        .lock()
        .take(MAX_SECRET_BYTES + 2)
        .read_to_end(&mut bytes)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    to_secret(bytes)
}

/// Read a secret from a file. One final newline is removed.
pub fn read_file_secret(path: &str) -> io::Result<SecretText> {
    let file = File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    file.take(MAX_SECRET_BYTES + 2).read_to_end(&mut bytes)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    to_secret(bytes)
}

/// Ask a yes or no question on the terminal. No terminal means no.
pub fn confirm(question: &str) -> bool {
    let Ok(mut tty) = open_tty() else {
        return false;
    };
    if tty
        .write_all(format!("{question} [y/N] ").as_bytes())
        .and_then(|()| tty.flush())
        .is_err()
    {
        return false;
    }
    let mut line = String::new();
    if BufReader::new(&tty).read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes" | "YES")
}

/// Write a line to the terminal, not to stdout. Without a terminal, to stderr.
pub fn tell(text: &str) {
    match open_tty() {
        Ok(mut tty) => {
            let _ = writeln!(tty, "{text}");
        }
        Err(_) => eprintln!("{text}"),
    }
}
