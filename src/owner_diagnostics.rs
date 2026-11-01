//! Narrow tracing sink for owner-window diagnostics. Never subscribes to other
//! application/dependency events, which may contain request or secret data.
use tracing::{Event, Metadata, Subscriber, span};

struct OwnerDiagnostics;
impl Subscriber for OwnerDiagnostics {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        matches!(
            metadata.target(),
            "apassy::broker::approvals::owner_window"
                | "apassy::broker::approvals::owner_auth"
                | "apassy::native::owner_lifecycle"
                | "apassy::desktop::owner_check"
        ) && *metadata.level() <= tracing::Level::INFO
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        #[derive(Default)]
        struct SafeFields(String);
        impl tracing::field::Visit for SafeFields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if matches!(
                    field.name(),
                    "message" | "reason" | "event" | "generation" | "heartbeat_age_ms" | "biometry"
                ) {
                    use std::fmt::Write;
                    let _ = write!(self.0, " {}={value:?}", field.name());
                }
            }
        }
        let mut fields = SafeFields::default();
        event.record(&mut fields);
        eprintln!("owner-window{}", fields.0);
    }
}
pub(super) fn install() {
    // Respect an embedding host's subscriber when it already installed one.
    let _ = tracing::subscriber::set_global_default(OwnerDiagnostics);
}
