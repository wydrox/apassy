//! Owner-check wording that differs by platform, as string literals for `concat!`:
//! macOS confirms with Touch ID or the passphrase, Linux with the vault passphrase or
//! system authentication (polkit, ADR 0045). A Linux user must never be told to use
//! Touch ID.

/// "Touch ID or the passphrase" on macOS.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! owner_check {
    () => {
        "Touch ID or the passphrase"
    };
}
/// "the passphrase or system authentication" on Linux.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! owner_check {
    () => {
        "the passphrase or system authentication"
    };
}

/// Where macOS names Touch ID alone ("needs Touch ID"): "Touch ID" on macOS.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! touch_id {
    () => {
        "Touch ID"
    };
}
/// Where macOS names Touch ID alone: the Linux owner check.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! touch_id {
    () => {
        "the passphrase or system authentication"
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn linux_wording_never_names_touch_id() {
        for text in [crate::owner_check!(), crate::touch_id!()] {
            assert_eq!(
                text.contains("Touch ID"),
                !cfg!(target_os = "linux"),
                "{text}"
            );
        }
    }
}
