//! Bouncer on a local Jev-compatible decision model (ADR 0007).
//!
//! The bouncer sends one `POST /v1/systemone` request with `noul` questions
//! and reads the probabilities. Laya (`laya-serve`) and Jev use this protocol.
//! Any failure gives [`BouncerVerdict::Unavailable`]. Unavailable is never an
//! allowance.

use std::time::Duration;

use serde_json::{Map, Value, json};

use super::http::{self, DestinationUrl, parse_destination};
use super::shell_risk::Analysis;
use crate::vault::{CALIBRATION_FLOOR, Declaration, PATTERN_APPROVALS_NEEDED, valid_model_version};

/// Version of the question set and the decision policy. Change it when either changes.
/// Version 3 adds the production rule (ADR 0010). Version 4 adds remembered patterns and
/// the calibrated `task_match` level at the model step (ADR 0009).
pub const BOUNCER_CONTRACT: &str = "apassy-bouncer-v4";
/// Default address of `laya-serve` in the operations guide.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8770";
/// Environment variable that changes the bouncer address.
pub const URL_ENV: &str = "APASSY_BOUNCER_URL";
/// The owner must decide when a needed answer is less certain than this (ADR 0008).
pub const MIN_CONFIDENCE: f64 = 0.8;
/// A "destroy" answer at or above this vetoes an unknown command.
const DESTROY_VETO: f64 = 0.9;
const PATH: &str = "/v1/systemone";
const TIMEOUT: Duration = Duration::from_secs(3);

/// Facts that the model answers. A decision model classifies facts well. A direct
/// "allow or ask" question gave probabilities near 0.5 in a probe on 2026-09-26.
const FACTS: [(&str, &str); 5] = [
    (
        "task_match",
        "Is the shell command a normal step to do what the user asked?",
    ),
    (
        "writes",
        "Does the shell command change data, files, settings, or state? Reading, listing, testing, and building do not change state.",
    ),
    (
        "remote",
        "Does the shell command act on a remote server, database, or cloud service?",
    ),
    (
        "leak",
        "Does the shell command print, encode, save, or send the value of a secret variable?",
    ),
    (
        "destroy",
        "Does the shell command delete, drop, truncate, reset, or overwrite data?",
    ),
];
const RULE_FACT: (&str, &str) = ("rule_break", "Does the shell command break the owner rule?");

/// What the bouncer sees. It has no secret value and no absolute path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BouncerRequest {
    /// The user's words that led the agent to this request. The agent supplies it.
    pub user_request: String,
    pub command: String,
    /// Working directory relative to the project directory. "." is the project root.
    pub relative_dir: String,
    pub purpose: String,
    pub env_names: Vec<String>,
    pub instruction: String,
}

/// One model answer: the probability that the fact is true.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub name: String,
    pub probability: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BouncerVerdict {
    /// All answers are present.
    Scored {
        facts: Vec<Fact>,
        /// The model version from the `model` field of the answer, for example
        /// `apassy-base-v1+1a2b3c4d` or `laya-rl-agent`. `None` when the field is
        /// missing or not a short version text.
        model: Option<String>,
    },
    /// The model did not give a valid answer. The reason has no request data.
    Unavailable(String),
}

/// A model version is short (`vault::MAX_MODEL_VERSION`) and has only letters, digits,
/// and `.`, `_`, `+`, `-`.
fn model_version(value: &Value) -> Option<String> {
    let text = value.get("model")?.as_str()?;
    valid_model_version(text).then(|| text.to_owned())
}

impl BouncerVerdict {
    pub fn fact(&self, name: &str) -> Option<f64> {
        match self {
            Self::Scored { facts, .. } => {
                facts.iter().find(|f| f.name == name).map(|f| f.probability)
            }
            Self::Unavailable(_) => None,
        }
    }

    /// The version of the model that answered, if it sent one.
    pub fn model(&self) -> Option<&str> {
        match self {
            Self::Scored { model, .. } => model.as_deref(),
            Self::Unavailable(_) => None,
        }
    }

    /// Short text for the activity log. No request data.
    pub fn summary(&self) -> String {
        match self {
            Self::Unavailable(reason) => format!("Bouncer unavailable: {reason}"),
            Self::Scored { facts, model } => {
                let answers = facts
                    .iter()
                    .map(|f| format!("{} {:.0}%", f.name, f.probability * 100.0))
                    .collect::<Vec<_>>()
                    .join(", ");
                match model {
                    Some(model) => format!("{answers}. Model: {model}"),
                    None => answers,
                }
            }
        }
    }
}

/// Client for one local decision service.
#[derive(Debug, Clone)]
pub struct BouncerClient {
    destination: DestinationUrl,
    url: String,
    api_key: Option<String>,
    timeout: Duration,
    /// The model version that the answers must name (goal item B9). A promoted model is
    /// pinned, so another model at the same address cannot change the policy silently.
    expected_model: Option<String>,
}

impl BouncerClient {
    /// Only a loopback `http://` address is permitted in this phase.
    pub fn new(url: &str) -> Result<Self, &'static str> {
        let destination = parse_destination(url)?;
        if !matches!(destination, DestinationUrl::Loopback { .. }) {
            return Err("The bouncer must run on this computer (http://127.0.0.1:PORT).");
        }
        Ok(Self {
            destination,
            url: url.trim().trim_end_matches('/').to_owned(),
            api_key: None,
            timeout: TIMEOUT,
            expected_model: None,
        })
    }

    /// A client for another loopback address, with the same key and time limit. It does
    /// not pin a model version.
    pub fn at_url(&self, url: &str) -> Result<Self, &'static str> {
        let mut client = Self::new(url)?;
        client.api_key.clone_from(&self.api_key);
        client.timeout = self.timeout;
        Ok(client)
    }

    /// Accept only answers that name `version` in their `model` field. Another version
    /// or no version gives [`BouncerVerdict::Unavailable`], so the owner decides.
    pub fn expect_model(mut self, version: &str) -> Self {
        self.expected_model = Some(version.to_owned());
        self
    }

    /// The pinned model version, if there is one.
    pub fn expected_model(&self) -> Option<&str> {
        self.expected_model.as_deref()
    }

    /// `APASSY_BOUNCER_URL`, or the default address.
    pub fn from_env() -> Result<Self, &'static str> {
        let url = std::env::var(URL_ENV)
            .ok()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_URL.to_owned());
        let mut client = Self::new(&url)?;
        client.api_key = std::env::var("APASSY_BOUNCER_KEY")
            .ok()
            .filter(|key| !key.is_empty());
        Ok(client)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn evaluate(&self, request: &BouncerRequest) -> BouncerVerdict {
        let body = request_body(request);
        let Ok(bytes) = serde_json::to_vec(&body) else {
            return BouncerVerdict::Unavailable("the request did not encode".to_owned());
        };
        let response = match http::post_json_loopback(
            &self.destination,
            PATH,
            &bytes,
            self.api_key.as_deref(),
            self.timeout,
        ) {
            Ok(response) => response,
            Err(_) => {
                return BouncerVerdict::Unavailable(format!("no answer from {}", self.url));
            }
        };
        if !(200..300).contains(&response.status) {
            return BouncerVerdict::Unavailable(format!("status {}", response.status));
        }
        let verdict = parse_answers(&response.body, &facts_for(request));
        match (&self.expected_model, &verdict) {
            (Some(expected), BouncerVerdict::Scored { model, .. })
                if model.as_deref() != Some(expected.as_str()) =>
            {
                BouncerVerdict::Unavailable(format!(
                    "the model at {} is {}, not the active version {expected}",
                    self.url,
                    model.as_deref().unwrap_or("unnamed")
                ))
            }
            _ => verdict,
        }
    }
}

/// Every question that the bouncer can ask, by name, in the order of the request. The
/// owner-rule question is last. The local fine-tune uses the same texts (goal item B9).
pub fn questions() -> Vec<(&'static str, &'static str)> {
    let mut all = FACTS.to_vec();
    all.push(RULE_FACT);
    all
}

fn facts_for(request: &BouncerRequest) -> Vec<(&'static str, &'static str)> {
    let mut facts = FACTS.to_vec();
    if !request.instruction.trim().is_empty() {
        facts.push(RULE_FACT);
    }
    facts
}

/// The Jev wire request. A short state with the user request gave the best
/// separation in the probe: normal commands 0.69 to 0.93 for `task_match`, risky
/// commands 0.04 to 0.28.
pub fn request_body(request: &BouncerRequest) -> Value {
    let mut questions = Map::new();
    for (name, text) in facts_for(request) {
        questions.insert(
            name.to_owned(),
            json!({ "type": "noul", "instructions": text }),
        );
    }
    json!({ "state": state_text(request), "questions": questions })
}

/// The state text that the model reads. The local fine-tune builds its examples with
/// this function, so a training state is the state that the broker sends.
pub fn state_text(request: &BouncerRequest) -> String {
    let mut state = format!(
        "User request: \"{}\". Shell command: `{}`.",
        request.user_request.trim(),
        request.command,
    );
    if !request.purpose.trim().is_empty() {
        state.push_str(&format!(
            " Agent's stated purpose: {}",
            request.purpose.trim()
        ));
    }
    if !request.instruction.trim().is_empty() {
        state.push_str(&format!(" Owner rule: {}", request.instruction.trim()));
    }
    state
}

/// Read `answers.<name>.noul` for every fact. A missing or bad value is unavailable.
/// The `model` field names the model version for the activity log (goal B8).
pub fn parse_answers(body: &[u8], asked: &[(&str, &str)]) -> BouncerVerdict {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return BouncerVerdict::Unavailable("the answer is not JSON".to_owned());
    };
    let mut facts = Vec::new();
    for (name, _) in asked {
        let probability = value
            .get("answers")
            .and_then(|answers| answers.get(*name))
            .and_then(|answer| answer.get("noul"))
            .and_then(Value::as_f64)
            .filter(|p| (0.0..=1.0).contains(p));
        match probability {
            Some(probability) => facts.push(Fact {
                name: (*name).to_owned(),
                probability,
            }),
            None => return BouncerVerdict::Unavailable(format!("no valid answer for {name}")),
        }
    }
    BouncerVerdict::Scored {
        facts,
        model: model_version(&value),
    }
}

/// The bouncer decision for one request.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub ask_owner: bool,
    /// Lowest certainty among the answers that the decision needed. `None` when the
    /// model did not decide.
    pub confidence: Option<f64>,
    /// Short text for the activity log and the approval card. No secret values.
    pub note: String,
}

/// What the policy knows besides the model answers.
#[derive(Debug, Clone)]
pub struct DecisionContext<'a> {
    pub analysis: &'a Analysis,
    /// One entry per requested item. `None` means that the item has no declaration.
    pub declarations: &'a [Option<Declaration>],
    pub has_user_request: bool,
}

/// Hard owner rules (ADR 0010). A run that matches one always waits for the owner.
///
/// [`decide`] checks these rules first. The model, remembered patterns, and calibrated
/// thresholds come after this check, so they cannot change its result. The broker does
/// not call the model for such a run.
pub fn owner_required(context: &DecisionContext<'_>) -> Option<String> {
    let production = context
        .declarations
        .iter()
        .flatten()
        .any(Declaration::is_production);
    production.then(|| {
        "Production credential: the owner approves every run with it (ADR 0010).".to_owned()
    })
}

/// Levels that the owner can change with a calibration (ADR 0009 step 3). The production
/// rule, the rule flags, the vetoes, and the read-only check are not here, so a
/// calibration cannot change them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// A command that is not known safe and not certainly read-only needs `task_match`
    /// at or above this level.
    pub task_match: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            task_match: MIN_CONFIDENCE,
        }
    }
}

impl Thresholds {
    /// The `task_match` level inside the calibration range. A calibration can make the
    /// level lower than the default, never lower than the floor.
    pub fn task_match_level(&self) -> f64 {
        if self.task_match.is_nan() {
            MIN_CONFIDENCE
        } else {
            self.task_match.clamp(CALIBRATION_FLOOR, MIN_CONFIDENCE)
        }
    }

    /// Text for the decision log.
    pub fn policy_label(&self) -> String {
        format!(
            "{BOUNCER_CONTRACT}; task_match {:.2}",
            self.task_match_level()
        )
    }
}

/// What learning gives one decision (ADR 0009). Both parts act only at the model step.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Learned {
    pub thresholds: Thresholds,
    /// An active remembered pattern that matches the request, as the owner sees it.
    pub pattern: Option<String>,
}

/// Combine the command analysis, the owner declarations, and the model facts (ADR 0008),
/// without learning. See [`decide_learned`].
pub fn decide(verdict: &BouncerVerdict, context: &DecisionContext<'_>) -> Decision {
    decide_learned(verdict, context, &Learned::default())
}

/// Combine the command analysis, the owner declarations, the model facts, and learning.
///
/// 1. A hard owner rule asks the owner: a production declaration ([`owner_required`]).
///    No later step can change this.
/// 2. A rule flag asks the owner. The model is not needed.
/// 3. A missing user request or declaration asks the owner.
/// 4. An active remembered pattern allows the run. It replaces only the model step
///    (steps 5 and 6), so it cannot change steps 1 to 3.
/// 5. The model decides. A command that is not known safe and not certainly read-only
///    must match the user request at the `task_match` level (80%, or a lower level
///    that the owner applied). A high-risk or irreversible credential also needs 80%
///    certainty that the command does not change state, unless the command is known safe.
/// 6. Model vetoes: "destroy" at 90% for an unknown command, "rule_break" at 80%.
///
/// The hard rules of the grant (ADR 0007) run before this function. A failure there is
/// a denial, so no step here can change it.
pub fn decide_learned(
    verdict: &BouncerVerdict,
    context: &DecisionContext<'_>,
    learned: &Learned,
) -> Decision {
    if let Some(decision) = before_model(context) {
        return decision;
    }
    if let Some(pattern) = &learned.pattern {
        return Decision {
            ask_owner: false,
            confidence: None,
            note: format!(
                "Remembered pattern allowed: {pattern}. The owner approved it {PATTERN_APPROVALS_NEEDED} times."
            ),
        };
    }
    model_step(verdict, context, learned.thresholds)
}

/// Steps 1 to 3 of [`decide_learned`]. `Some` when the owner decides before any model
/// or learning step.
pub fn before_model(context: &DecisionContext<'_>) -> Option<Decision> {
    let ask = |note: String| {
        Some(Decision {
            ask_owner: true,
            confidence: None,
            note,
        })
    };
    if let Some(mut note) = owner_required(context) {
        if !context.analysis.flags.is_empty() {
            note.push_str(&format!(
                " Rule flags: {}.",
                context.analysis.flags.join(", ")
            ));
        }
        return ask(note);
    }
    if !context.analysis.flags.is_empty() {
        return ask(format!("Rule flags: {}", context.analysis.flags.join(", ")));
    }
    if !context.has_user_request {
        return ask("The agent did not send the user request.".to_owned());
    }
    if context.declarations.iter().any(Option::is_none) {
        return ask("An item has no declaration.".to_owned());
    }
    None
}

fn model_step(
    verdict: &BouncerVerdict,
    context: &DecisionContext<'_>,
    thresholds: Thresholds,
) -> Decision {
    let ask = |confidence, note: String| Decision {
        ask_owner: true,
        confidence,
        note,
    };
    let BouncerVerdict::Scored { .. } = verdict else {
        return ask(None, verdict.summary());
    };
    let sensitive = context
        .declarations
        .iter()
        .flatten()
        .any(Declaration::is_sensitive);
    let known_safe = context.analysis.known_safe;
    let certain_read = verdict
        .fact("writes")
        .is_some_and(|p| 1.0 - p >= MIN_CONFIDENCE);
    // Needed facts: (fact, must be true, needed certainty).
    // - A command that is not known safe and not certainly read-only must match the
    //   user request. A read cannot change anything, so it does not need the match.
    // - A sensitive credential needs a certain "does not change state", unless the
    //   command is known safe (local work or a read by rule).
    let mut needed: Vec<(&str, bool, f64)> = Vec::new();
    let task_level = thresholds.task_match_level();
    if !known_safe && !certain_read {
        needed.push(("task_match", true, task_level));
    }
    if sensitive && !known_safe {
        needed.push(("writes", false, MIN_CONFIDENCE));
    }
    let mut failed = Vec::new();
    let mut confidence: f64 = 1.0;
    for (name, want_true, level) in needed {
        let p = verdict.fact(name).unwrap_or(0.5);
        let support = if want_true { p } else { 1.0 - p };
        confidence = confidence.min(support);
        if support < level {
            failed.push(format!(
                "{name} {}{:.0}%",
                if want_true { "" } else { "not " },
                support * 100.0
            ));
        }
    }
    // Vetoes. The rules find secret output and cache removal, so the model's "leak"
    // answer is not a veto: it gave 0.8 or more for plain file reads on real commands.
    // "destroy" is a veto at 90% for commands that the rules do not know.
    let mut vetoes: Vec<(&str, f64)> = vec![("rule_break", MIN_CONFIDENCE)];
    if !known_safe {
        vetoes.push(("destroy", DESTROY_VETO));
    }
    for (name, level) in vetoes {
        if let Some(p) = verdict.fact(name)
            && p >= level
        {
            failed.push(format!("{name} {:.0}%", p * 100.0));
            confidence = confidence.min(1.0 - p);
        }
    }
    let scope = if sensitive {
        "sensitive credential"
    } else {
        "normal credential"
    };
    let calibrated = if task_level < MIN_CONFIDENCE {
        format!(" Calibrated task_match level: {:.0}%.", task_level * 100.0)
    } else {
        String::new()
    };
    if failed.is_empty() {
        Decision {
            ask_owner: false,
            confidence: Some(confidence),
            note: format!(
                "Model allowed at {:.0}% certainty ({scope}{}). {}{calibrated}",
                confidence * 100.0,
                if known_safe {
                    ", known safe command"
                } else {
                    ""
                },
                verdict.summary()
            ),
        }
    } else {
        ask(
            Some(confidence),
            format!(
                "Below {:.0}% certainty: {}. {}{calibrated}",
                MIN_CONFIDENCE * 100.0,
                failed.join(", "),
                verdict.summary()
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Environment, Reversibility, RiskLevel, Scope};

    fn request(instruction: &str) -> BouncerRequest {
        BouncerRequest {
            user_request: "Apply the staging migration".to_owned(),
            command: "npm run migrate".to_owned(),
            relative_dir: ".".to_owned(),
            purpose: "Apply migrations".to_owned(),
            env_names: vec!["DB_URL".to_owned()],
            instruction: instruction.to_owned(),
        }
    }

    fn verdict(pairs: &[(&str, f64)]) -> BouncerVerdict {
        BouncerVerdict::Scored {
            facts: pairs
                .iter()
                .map(|(n, p)| Fact {
                    name: (*n).to_owned(),
                    probability: *p,
                })
                .collect(),
            model: None,
        }
    }

    /// Goal B8: the activity log names the model version that answered.
    #[test]
    fn answer_names_the_model_version() {
        let asked = [("task_match", ""), ("writes", "")];
        let body = |model: &str| {
            format!(
                r#"{{"model":{model},"answers":{{"task_match":{{"noul":0.9}},"writes":{{"noul":0.1}}}}}}"#
            )
        };
        let base = parse_answers(body("\"apassy-base-v1+1a2b3c4d\"").as_bytes(), &asked);
        assert_eq!(base.model(), Some("apassy-base-v1+1a2b3c4d"));
        assert_eq!(
            base.summary(),
            "task_match 90%, writes 10%. Model: apassy-base-v1+1a2b3c4d"
        );
        let stock = parse_answers(body("\"laya-rl-agent\"").as_bytes(), &asked);
        assert_eq!(stock.model(), Some("laya-rl-agent"));
        // A missing, long, or odd model text is not recorded. The answers still count.
        let long = format!("\"{}\"", "a".repeat(crate::vault::MAX_MODEL_VERSION + 1));
        for odd in ["null", "7", "\"\"", "\"a b\"", "\"x\\ny\"", long.as_str()] {
            let verdict = parse_answers(body(odd).as_bytes(), &asked);
            assert_eq!(verdict.model(), None, "{odd}");
            assert_eq!(verdict.summary(), "task_match 90%, writes 10%");
        }
        let without = br#"{"answers":{"task_match":{"noul":0.9},"writes":{"noul":0.1}}}"#;
        assert_eq!(parse_answers(without, &asked).model(), None);
    }

    fn declaration(environment: Environment) -> Option<Declaration> {
        Some(Declaration {
            project: "odealo".to_owned(),
            environment,
            risk: RiskLevel::Medium,
            scope: Scope::ReadWrite,
            reversibility: Reversibility::Reversible,
        })
    }

    #[test]
    fn body_has_user_request_and_rule_fact_only_with_instruction() {
        let plain = request_body(&request(""));
        assert_eq!(plain["questions"].as_object().map(Map::len), Some(5));
        let state = plain["state"].as_str().unwrap_or_default();
        assert!(state.starts_with("User request: \"Apply the staging migration\""));
        let ruled = request_body(&request("Staging only."));
        assert_eq!(ruled["questions"].as_object().map(Map::len), Some(6));
        assert!(
            ruled["state"]
                .as_str()
                .unwrap_or_default()
                .ends_with("Owner rule: Staging only.")
        );
    }

    #[test]
    fn policy() {
        let analysis = Analysis::default();
        let staging = [declaration(Environment::Staging)];
        let high_risk = [Some(Declaration {
            risk: RiskLevel::High,
            ..declaration(Environment::Staging).expect("declaration")
        })];
        let run = |v: &BouncerVerdict, d: &[Option<Declaration>], user: bool| {
            decide(
                v,
                &DecisionContext {
                    analysis: &analysis,
                    declarations: d,
                    has_user_request: user,
                },
            )
        };
        let clean = verdict(&[
            ("task_match", 0.9),
            ("writes", 0.8),
            ("leak", 0.05),
            ("destroy", 0.1),
        ]);
        assert!(!run(&clean, &staging, true).ask_owner);
        // A high-risk credential needs a certain read-only command.
        assert!(run(&clean, &high_risk, true).ask_owner);
        let read = verdict(&[
            ("task_match", 0.9),
            ("writes", 0.1),
            ("leak", 0.05),
            ("destroy", 0.1),
        ]);
        assert!(!run(&read, &high_risk, true).ask_owner);
        // A certain read does not need the task match. A leak answer is not a veto.
        let read_unmatched = verdict(&[
            ("task_match", 0.3),
            ("writes", 0.1),
            ("leak", 0.9),
            ("destroy", 0.1),
        ]);
        assert!(!run(&read_unmatched, &staging, true).ask_owner);
        for bad in [
            verdict(&[("task_match", 0.75), ("writes", 0.5), ("destroy", 0.1)]),
            verdict(&[("task_match", 0.9), ("writes", 0.5), ("destroy", 0.95)]),
            verdict(&[
                ("task_match", 0.9),
                ("writes", 0.5),
                ("destroy", 0.1),
                ("rule_break", 0.85),
            ]),
        ] {
            let d = run(&bad, &staging, true);
            assert!(d.ask_owner, "{d:?}");
            assert!(d.confidence.is_some_and(|c| c < MIN_CONFIDENCE));
        }
        assert!(run(&clean, &staging, false).ask_owner, "no user request");
        assert!(run(&clean, &[None], true).ask_owner, "no declaration");
        assert!(run(&BouncerVerdict::Unavailable("x".into()), &staging, true).ask_owner);
    }

    /// ADR 0010: a production declaration always waits for the owner. Known safe and
    /// read-only commands and a fully certain model verdict do not change this.
    #[test]
    fn production_always_asks_the_owner() {
        let certain = verdict(&[
            ("task_match", 1.0),
            ("writes", 0.0),
            ("remote", 0.0),
            ("leak", 0.0),
            ("destroy", 0.0),
            ("rule_break", 0.0),
        ]);
        let read_only = verdict(&[
            ("task_match", 0.3),
            ("writes", 0.0),
            ("remote", 0.0),
            ("leak", 0.0),
            ("destroy", 0.0),
        ]);
        // The mildest production declaration: low risk, read-only, reversible.
        let mild = Declaration {
            project: "odealo".to_owned(),
            environment: Environment::Production,
            risk: RiskLevel::Low,
            scope: Scope::ReadOnly,
            reversibility: Reversibility::Reversible,
        };
        let sets: [&[Option<Declaration>]; 3] = [
            &[Some(mild.clone())],
            &[declaration(Environment::Staging), Some(mild.clone())],
            &[declaration(Environment::Production)],
        ];
        let known_safe = Analysis {
            flags: Vec::new(),
            known_safe: true,
        };
        let unknown = Analysis::default();
        for declarations in sets {
            for analysis in [&known_safe, &unknown] {
                for model in [
                    &certain,
                    &read_only,
                    &BouncerVerdict::Unavailable("not asked".into()),
                ] {
                    let context = DecisionContext {
                        analysis,
                        declarations,
                        has_user_request: true,
                    };
                    let decision = decide(model, &context);
                    assert!(
                        decision.ask_owner,
                        "{declarations:?} {analysis:?} {model:?}"
                    );
                    assert_eq!(decision.confidence, None, "the model did not decide");
                    assert!(decision.note.starts_with("Production credential"));
                    assert!(owner_required(&context).is_some());
                }
            }
        }
        // The same fully certain verdict runs a staging credential without the owner.
        let staging = [declaration(Environment::Staging)];
        let context = DecisionContext {
            analysis: &known_safe,
            declarations: &staging,
            has_user_request: true,
        };
        assert!(owner_required(&context).is_none());
        assert!(!decide(&certain, &context).ask_owner);
    }

    /// ADR 0010: a remembered pattern and a calibrated level act only at the model step.
    /// The production rule, a rule flag, a missing user request, and a missing
    /// declaration still ask the owner, with the same note as without learning.
    #[test]
    fn learning_replaces_only_the_model_step() {
        let learned = Learned {
            thresholds: Thresholds {
                task_match: CALIBRATION_FLOOR,
            },
            pattern: Some("npm run <string>".to_owned()),
        };
        let certain = verdict(&[("task_match", 1.0), ("writes", 0.0), ("destroy", 0.0)]);
        let staging = [declaration(Environment::Staging)];
        let production = [declaration(Environment::Production)];
        let clean = Analysis::default();
        let flagged = Analysis {
            flags: vec!["secret_output".to_owned()],
            known_safe: false,
        };
        let cases: [(&Analysis, &[Option<Declaration>], bool, &str); 4] = [
            (&clean, &production, true, "Production credential"),
            (&flagged, &staging, true, "Rule flags: secret_output"),
            (
                &clean,
                &staging,
                false,
                "The agent did not send the user request.",
            ),
            (&clean, &[None], true, "An item has no declaration."),
        ];
        for (analysis, declarations, has_user_request, note) in cases {
            let context = DecisionContext {
                analysis,
                declarations,
                has_user_request,
            };
            let with = decide_learned(&certain, &context, &learned);
            assert!(with.ask_owner, "{note}");
            assert_eq!(with.confidence, None);
            assert!(with.note.starts_with(note), "{}", with.note);
            assert_eq!(with, decide(&certain, &context), "learning changed {note}");
            assert!(before_model(&context).is_some());
        }

        // A clean request: the pattern replaces the model, also an unavailable model and
        // a model veto. Without the pattern, both ask.
        let context = DecisionContext {
            analysis: &clean,
            declarations: &staging,
            has_user_request: true,
        };
        let veto = verdict(&[("task_match", 0.9), ("writes", 0.5), ("destroy", 0.99)]);
        for model in [&veto, &BouncerVerdict::Unavailable("not asked".into())] {
            assert!(decide(model, &context).ask_owner);
            let allowed = decide_learned(model, &context, &learned);
            assert!(!allowed.ask_owner, "{allowed:?}");
            assert!(
                allowed
                    .note
                    .starts_with("Remembered pattern allowed: npm run <string>")
            );
        }
    }

    /// ADR 0009 step 3: a calibration changes only the `task_match` level, inside
    /// [`CALIBRATION_FLOOR`, 0.8]. The read-only check for a sensitive credential and
    /// the vetoes stay.
    #[test]
    fn calibration_changes_only_the_task_match_level() {
        let analysis = Analysis::default();
        let staging = [declaration(Environment::Staging)];
        let high_risk = [Some(Declaration {
            risk: RiskLevel::High,
            ..declaration(Environment::Staging).expect("declaration")
        })];
        let run = |v: &BouncerVerdict, d: &[Option<Declaration>], level: f64| {
            decide_learned(
                v,
                &DecisionContext {
                    analysis: &analysis,
                    declarations: d,
                    has_user_request: true,
                },
                &Learned {
                    thresholds: Thresholds { task_match: level },
                    pattern: None,
                },
            )
        };
        let general = verdict(&[("task_match", 0.65), ("writes", 0.5), ("destroy", 0.1)]);
        assert!(run(&general, &staging, 0.8).ask_owner);
        let calibrated = run(&general, &staging, 0.6);
        assert!(!calibrated.ask_owner, "{calibrated:?}");
        assert!(calibrated.note.contains("Calibrated task_match level: 60%"));
        // A level under the floor is the floor. A level over 0.8 is 0.8.
        let weak = verdict(&[("task_match", 0.45), ("writes", 0.5), ("destroy", 0.1)]);
        assert!(run(&weak, &staging, 0.1).ask_owner);
        assert!(run(&weak, &staging, f64::NAN).ask_owner);
        assert_eq!(
            Thresholds { task_match: 0.95 }.task_match_level(),
            MIN_CONFIDENCE
        );
        // The sensitive read-only check and the vetoes do not move.
        let writes = verdict(&[("task_match", 0.95), ("writes", 0.5), ("destroy", 0.1)]);
        assert!(run(&writes, &high_risk, CALIBRATION_FLOOR).ask_owner);
        let destroy = verdict(&[("task_match", 0.95), ("writes", 0.5), ("destroy", 0.95)]);
        assert!(run(&destroy, &staging, CALIBRATION_FLOOR).ask_owner);
        let rule = verdict(&[
            ("task_match", 0.95),
            ("writes", 0.5),
            ("destroy", 0.1),
            ("rule_break", 0.85),
        ]);
        assert!(run(&rule, &staging, CALIBRATION_FLOOR).ask_owner);
    }

    /// A loopback server that gives `body` to each of `requests` requests.
    fn answer_server(body: &'static str, requests: usize) -> String {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            for stream in listener.incoming().take(requests).flatten() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut request = vec![0u8; length];
                let _ = reader.read_exact(&mut request);
                let mut stream = stream;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        url
    }

    /// Goal item B9: a promoted model is pinned to its version. An answer from another
    /// version is not a verdict, so the owner decides.
    #[test]
    fn a_pinned_client_accepts_only_its_model_version() {
        let body = r#"{"model":"apassy-local-v1+11111111","answers":{"task_match":{"noul":0.9},"writes":{"noul":0.1},"remote":{"noul":0.1},"leak":{"noul":0.1},"destroy":{"noul":0.1}}}"#;
        let url = answer_server(body, 3);
        let client = BouncerClient::new(&url).expect("loopback");
        assert_eq!(client.expected_model(), None);
        assert!(matches!(
            client.evaluate(&request("")),
            BouncerVerdict::Scored { .. }
        ));
        let pinned = client.clone().expect_model("apassy-local-v1+11111111");
        assert_eq!(pinned.expected_model(), Some("apassy-local-v1+11111111"));
        assert_eq!(
            pinned.evaluate(&request("")).model(),
            Some("apassy-local-v1+11111111")
        );
        let other = client.expect_model("apassy-local-v1+22222222");
        match other.evaluate(&request("")) {
            BouncerVerdict::Unavailable(reason) => assert!(
                reason.contains("is apassy-local-v1+11111111, not the active version"),
                "{reason}"
            ),
            verdict => panic!("a wrong version gave a verdict: {verdict:?}"),
        }
        // `at_url` keeps the key and the time limit, and drops the pin.
        let moved = other.at_url("http://127.0.0.1:9").expect("loopback");
        assert_eq!(moved.expected_model(), None);
        assert!(other.at_url("https://example.com").is_err());
    }

    #[test]
    fn only_loopback_and_unreachable_is_unavailable() {
        assert!(BouncerClient::new("https://example.com").is_err());
        let client = BouncerClient::new("http://127.0.0.1:9")
            .expect("loopback")
            .with_timeout(Duration::from_millis(300));
        assert!(matches!(
            client.evaluate(&request("")),
            BouncerVerdict::Unavailable(_)
        ));
    }
}
