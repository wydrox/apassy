//! Process-lifetime route observations. This payload cannot hold request data.
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum ReasonKind {
    #[default]
    Other,
    MissingTask,
    LowTaskMatch,
    ModelUnavailable,
    ModelTimeout,
    HookFlags,
    HookUnverified,
    HookAmbiguous,
    NotProject,
    AlwaysAsk,
    Production,
    ForeignHost,
    ForeignProject,
    MissingDeclaration,
    UnfitAnswer,
    OneTimeCode,
    ModelUnsure,
    AccessCheck,
    Connector,
    ModelAllowed,
    RememberedAnswer,
    RememberedPattern,
}
impl ReasonKind {
    pub fn headline(self) -> &'static str {
        match self {
            Self::MissingTask => "The agent didn't say what you asked it to do.",
            Self::LowTaskMatch => "The bouncer wasn't sure this fits your task.",
            Self::ModelUnavailable => "No bouncer is running.",
            Self::ModelTimeout => "The bouncer didn't answer in time.",
            Self::HookUnverified => "The agent task could not be verified in the host transcript.",
            Self::HookAmbiguous => "More than one agent session could be the source of this task.",
            Self::HookFlags => "The command or task context needs your review.",
            Self::NotProject => "This folder isn't a project.",
            Self::AlwaysAsk => "This credential is marked Always ask.",
            Self::Production => "Production credential.",
            Self::ForeignHost => "This host isn't declared for this credential.",
            Self::ForeignProject => "This credential belongs to another project.",
            Self::MissingDeclaration => "This credential has no declaration.",
            Self::UnfitAnswer => "Your earlier answer doesn't cover this run.",
            Self::OneTimeCode => "This run needs a one-time code.",
            Self::ModelUnsure => "The bouncer wasn't sure this run is safe.",
            Self::AccessCheck => "This request didn't pass the access checks.",
            Self::Connector => "This connector operation needs your approval.",
            Self::ModelAllowed => "The bouncer allowed this run.",
            Self::RememberedAnswer => "Your earlier answer covers this run.",
            Self::RememberedPattern => "An approved pattern covers this run.",
            Self::Other => "This request needs your approval.",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteKind {
    Bouncer,
    Owner,
    Answer,
    Pattern,
    Connector,
    Refused,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerdictKind {
    Allowed,
    Asked,
    Refused,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LatencyBucket {
    UnderSecond,
    UnderTenSeconds,
    TenSecondsOrMore,
}
impl LatencyBucket {
    pub fn of(elapsed: Duration) -> Self {
        match elapsed.as_secs() {
            0 => Self::UnderSecond,
            1..10 => Self::UnderTenSeconds,
            _ => Self::TenSecondsOrMore,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskMatchBucket {
    NotScored,
    Below50,
    From50To79,
    AtLeast80,
}
impl TaskMatchBucket {
    pub fn of(score: Option<f64>) -> Self {
        match score {
            None => Self::NotScored,
            Some(p) if p < 0.5 => Self::Below50,
            Some(p) if p < 0.8 => Self::From50To79,
            Some(_) => Self::AtLeast80,
        }
    }
}
/// Deliberately closed: no strings, identifiers, floats, durations or request objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteEvent {
    pub route: RouteKind,
    pub reason: ReasonKind,
    pub inference_attempted: bool,
    pub verdict: VerdictKind,
    pub latency: LatencyBucket,
    pub task_match: TaskMatchBucket,
}
#[derive(Default, Clone)]
pub struct Counters {
    pub outcomes: BTreeMap<RouteEvent, u64>,
}
impl Counters {
    fn record(&mut self, event: RouteEvent) {
        *self.outcomes.entry(event).or_default() += 1;
    }
    pub fn summary(&self) -> String {
        let mut allowed = 0;
        let mut refused = 0;
        let mut asked = 0;
        for (e, n) in &self.outcomes {
            if e.inference_attempted {
                match e.verdict {
                    VerdictKind::Allowed => allowed += n,
                    VerdictKind::Refused => refused += n,
                    VerdictKind::Asked => {}
                }
            }
            if e.verdict == VerdictKind::Asked {
                asked += n;
            }
        }
        format!(
            "Since Apassy started: decided by the bouncer {} (allowed {allowed}, refused {refused}); asked you {asked}",
            allowed + refused
        )
    }
    pub fn top_reasons(&self) -> Vec<(ReasonKind, u64)> {
        let mut reasons = BTreeMap::new();
        for (e, n) in &self.outcomes {
            if e.verdict == VerdictKind::Asked {
                *reasons.entry(e.reason).or_insert(0) += n;
            }
        }
        let mut reasons: Vec<_> = reasons.into_iter().collect();
        reasons.sort_by_key(|(reason, count)| (std::cmp::Reverse(*count), *reason));
        reasons.truncate(5);
        reasons
    }
}
static COUNTERS: LazyLock<Mutex<Counters>> = LazyLock::new(|| Mutex::new(Counters::default()));
pub fn snapshot() -> Counters {
    COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}
pub(super) fn record(event: RouteEvent) {
    COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .record(event);
    tracing::info!(target: "apassy::broker::route", route = ?event.route, reason = ?event.reason,
        inference_attempted = event.inference_attempted, verdict = ?event.verdict,
        latency = ?event.latency, task_match = ?event.task_match);
}
/// Records early access refusals too, once per request; normal routes replace it.
pub(super) struct Attempt {
    start: std::time::Instant,
    recorded: bool,
    pub event: RouteEvent,
}
impl Attempt {
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            recorded: false,
            event: RouteEvent {
                route: RouteKind::Refused,
                reason: ReasonKind::AccessCheck,
                inference_attempted: false,
                verdict: VerdictKind::Refused,
                latency: LatencyBucket::UnderSecond,
                task_match: TaskMatchBucket::NotScored,
            },
        }
    }
    pub fn finish_route(&mut self) {
        self.event.latency = LatencyBucket::of(self.start.elapsed());
        record(self.event);
        self.recorded = true;
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.recorded {
            self.finish_route();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_payload_and_counters_distinguish_attempted_inference() {
        let event = RouteEvent {
            route: RouteKind::Owner,
            reason: ReasonKind::ModelUnavailable,
            inference_attempted: false,
            verdict: VerdictKind::Asked,
            latency: LatencyBucket::UnderSecond,
            task_match: TaskMatchBucket::NotScored,
        };
        // Exhaustive destructuring makes adding any field require reviewing this contract.
        let RouteEvent {
            route,
            reason,
            inference_attempted,
            verdict,
            latency,
            task_match,
        } = event;
        let _: (
            RouteKind,
            ReasonKind,
            bool,
            VerdictKind,
            LatencyBucket,
            TaskMatchBucket,
        ) = (
            route,
            reason,
            inference_attempted,
            verdict,
            latency,
            task_match,
        );
        let mut counts = Counters::default();
        counts.record(event);
        let attempted = RouteEvent {
            inference_attempted: true,
            ..event
        };
        counts.record(attempted);
        assert_eq!(counts.outcomes.len(), 2);
        assert_eq!(counts.outcomes[&event], 1);
        assert_eq!(counts.outcomes[&attempted], 1);
        assert!(counts.summary().ends_with("asked you 2"));
        assert_eq!(
            counts.top_reasons(),
            vec![(ReasonKind::ModelUnavailable, 2)]
        );
    }
}
