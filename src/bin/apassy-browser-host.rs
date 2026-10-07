//! `apassy-browser-host`: the native messaging host of the Apassy browser extension
//! (ADR 0021). The browser starts it; it passes each message to the browser socket of
//! the app. See [`apassy::browser::relay`].

fn main() {
    std::process::exit(apassy::browser::relay::main());
}
