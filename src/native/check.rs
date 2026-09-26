//! `apassy --notify-check STEP`: the owner check of goal item N1.
//!
//! `scripts/n1-check.sh` runs these steps with the signed `Apassy.app`. Each step
//! uses the real path of the app: [`NativeHelper::locate`], the notifier in
//! `Contents/Helpers/ApassyNotify.app` as a child of `apassy`, and the caller check
//! of the notifier. The agent name is the fixed text `n1-check`, so a check never
//! shows other text (goal item N2).
//!
//! Each output line is `KEY=VALUE` pairs after a step name. Times are Unix seconds
//! with millisecond precision.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    AlertStyle, NativeError, NativeHelper, Notification, NotificationAuthorization,
    NotificationEvent, NotificationSetting, NotificationStatus,
};

/// The agent name in the check notifications.
pub const CHECK_AGENT: &str = "n1-check";

/// Run one step and print its lines. Returns the process exit code.
pub fn run_notify_check(step: &str) -> i32 {
    let helper = match NativeHelper::locate() {
        Ok(helper) => helper,
        Err(err) => return fail("locate", &err),
    };
    match step {
        "status" => match helper.notify_status() {
            Ok(status) => {
                println!("status {}", status_pairs(&status));
                0
            }
            Err(err) => fail("status", &err),
        },
        "authorize" => {
            let started = now();
            match helper.notify_authorize() {
                Ok(status) => {
                    println!(
                        "authorize started_at={started:.3} answered_at={:.3} {}",
                        now(),
                        status_pairs(&status)
                    );
                    0
                }
                Err(err) => fail("authorize", &err),
            }
        }
        "post" => {
            let stamp = (now() * 1000.0) as u64;
            let mut code = 0;
            for (name, event) in [
                ("waiting", NotificationEvent::ApprovalWaiting),
                ("blocked", NotificationEvent::RequestBlocked),
            ] {
                let id = format!("n1-check-{name}-{stamp}");
                let notification = match Notification::new(&id, CHECK_AGENT, event) {
                    Ok(notification) => notification,
                    Err(err) => return fail("post", &err),
                };
                let requested = now();
                match helper.notify(&notification) {
                    Ok(outcome) => println!(
                        "post event={} id={id} requested_at={requested:.3} answered_at={:.3} delivered={} {}",
                        event.as_wire(),
                        now(),
                        outcome.delivered,
                        status_pairs(&outcome.status)
                    ),
                    Err(err) => code = fail("post", &err),
                }
            }
            code
        }
        _ => {
            eprintln!("apassy --notify-check takes status, authorize, or post.");
            2
        }
    }
}

fn fail(step: &str, err: &NativeError) -> i32 {
    let code = err.code().map_or("client", |code| code.as_str());
    println!("{step} error={code} message={err}");
    1
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

fn status_pairs(status: &NotificationStatus) -> String {
    let authorization = match status.authorization {
        NotificationAuthorization::NotDetermined => "not_determined",
        NotificationAuthorization::Denied => "denied",
        NotificationAuthorization::Authorized => "authorized",
        NotificationAuthorization::Provisional => "provisional",
        NotificationAuthorization::Unknown => "unknown",
    };
    let alert_style = match status.alert_style {
        AlertStyle::None => "none",
        AlertStyle::Banner => "banner",
        AlertStyle::Alert => "alert",
        AlertStyle::Unknown => "unknown",
    };
    format!(
        "authorization={authorization} alert={} alert_style={alert_style} notification_center={} can_deliver={}",
        setting(status.alert),
        setting(status.notification_center),
        status.can_deliver()
    )
}

fn setting(value: NotificationSetting) -> &'static str {
    match value {
        NotificationSetting::NotSupported => "not_supported",
        NotificationSetting::Disabled => "disabled",
        NotificationSetting::Enabled => "enabled",
        NotificationSetting::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_pairs_name_each_field() {
        let status = NotificationStatus {
            authorization: NotificationAuthorization::Authorized,
            alert: NotificationSetting::Enabled,
            alert_style: AlertStyle::Banner,
            notification_center: NotificationSetting::Enabled,
            lock_screen: NotificationSetting::Disabled,
            sound: NotificationSetting::NotSupported,
        };
        assert_eq!(
            status_pairs(&status),
            "authorization=authorized alert=enabled alert_style=banner notification_center=enabled can_deliver=true"
        );
        assert!(
            Notification::new(
                "n1-check-waiting-1",
                CHECK_AGENT,
                NotificationEvent::ApprovalWaiting
            )
            .is_ok()
        );
    }
}
