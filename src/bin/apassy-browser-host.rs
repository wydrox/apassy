//! `apassy-browser-host`: the native messaging host of the Apassy browser extension
//! (ADR 0021). The browser starts it; it passes each message to the browser socket of
//! the app. See [`apassy::browser::relay`].

fn main() {
    // ADR 0011 stage 6: first, before anything reads a secret.
    apassy::harden::harden_process_or_exit("apassy-browser-host");
    std::process::exit(apassy::browser::relay::main());
}
