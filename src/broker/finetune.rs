//! Local fine-tune of the bouncer model with the gate of ADR 0010 (goal item B9).
//!
//! The owner starts a training in the Learning view. Nothing starts a training by
//! itself. [`train`] does these steps:
//!
//! 1. The gate: 300 or more owner decisions with 30 or more owner denials in the
//!    decision log ([`gate`]), and AC power ([`power_now`], `/usr/bin/pmset -g batt`).
//!    A closed gate stops here. The trainer does not start.
//! 2. The decision log export (`apassy-decision-v1`) becomes training examples
//!    ([`examples_from_export`]). The label mapping is in `docs/operations/fine-tune.md`.
//! 3. The trainer (`tools/finetune/local_train.py`, which runs
//!    `tools/basemodel/train.py`, heads only, from the shipped base checkpoint) runs in
//!    its own process group. The broker stops the whole group after one hour, when the
//!    Mac leaves AC power, or when the owner stops it.
//! 4. The candidate goes to the vault in shadow mode ([`super::shadow`]). It has no
//!    effect until the owner promotes it.
//!
//! The example files contain commands and user requests. They stay in a folder with
//! mode `0700` on this computer, and [`train`] deletes them when the trainer ends.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use super::SharedVault;
use super::bouncer::{self, BouncerRequest};
use super::decide::lock;
use super::learning;
use crate::vault::{CandidateRecord, DecidedBy, DecisionRecord, NewCandidate, valid_model_version};

/// Owner decisions that a training needs (ADR 0010).
pub const MIN_OWNER_DECISIONS: usize = 300;
/// Owner denials among them that a training needs (ADR 0010).
pub const MIN_OWNER_DENIALS: usize = 30;
/// The hard time limit of one training (ADR 0010). The broker stops the trainer then.
pub const TIME_LIMIT: Duration = Duration::from_secs(3600);
/// How often the broker checks the power source during a training.
pub const POWER_CHECK_EVERY: Duration = Duration::from_secs(30);
/// The power source command. An absolute path, so `PATH` cannot change it.
pub const PMSET: &str = "/usr/bin/pmset";
/// The name of a local candidate. The version is `<name>+<first 8 hex of its SHA-256>`.
pub const LOCAL_MODEL_NAME: &str = "apassy-local-v1";
/// Export line format (`docs/operations/learning.md`).
const EXPORT_SCHEMA: &str = "apassy-decision-v1";
const POLL: Duration = Duration::from_millis(100);
/// Share of the commands in the validation part, in percent.
const VAL_PERCENT: u64 = 20;
/// Identical examples beyond this count are dropped, so one repeated request does not
/// fill the set.
const MAX_COPIES: usize = 3;
/// A denial counts at least this many times, and at most `MAX_DENIAL_WEIGHT` times.
const MIN_DENIAL_WEIGHT: usize = 2;
const MAX_DENIAL_WEIGHT: usize = 10;
/// Effect questions that keep the answer of the starting model (teacher examples).
const KEEP_QUESTIONS: [&str; 3] = ["writes", "remote", "destroy"];
const MAX_LOG_LINE: usize = 200;

/// The power source of this Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    Ac,
    Battery,
    /// `pmset` did not run or gave another source (for example a UPS). The gate stays
    /// closed.
    Unknown,
}

impl Power {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ac => "AC power",
            Self::Battery => "battery",
            Self::Unknown => "unknown",
        }
    }
}

/// Read the output of `pmset -g batt`. The first line names the source:
/// `Now drawing from 'AC Power'` or `Now drawing from 'Battery Power'`.
pub fn parse_pmset(output: &str) -> Power {
    match output.lines().find(|line| line.contains("drawing from")) {
        Some(line) if line.contains("'AC Power'") => Power::Ac,
        Some(line) if line.contains("'Battery Power'") => Power::Battery,
        _ => Power::Unknown,
    }
}

/// The power source now, from `/usr/bin/pmset -g batt`. A failure is `Unknown`.
pub fn power_now() -> Power {
    match Command::new(PMSET)
        .args(["-g", "batt"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => {
            parse_pmset(&String::from_utf8_lossy(&output.stdout))
        }
        _ => Power::Unknown,
    }
}

/// The training gate of ADR 0010.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrainingGate {
    pub owner_decisions: usize,
    pub owner_denials: usize,
    pub power: Power,
}

impl TrainingGate {
    pub fn is_open(&self) -> bool {
        self.owner_decisions >= MIN_OWNER_DECISIONS
            && self.owner_denials >= MIN_OWNER_DENIALS
            && self.power == Power::Ac
    }

    /// Why the gate is closed. Empty when it is open.
    pub fn reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.owner_decisions < MIN_OWNER_DECISIONS {
            reasons.push(format!(
                "{} of {MIN_OWNER_DECISIONS} owner decisions",
                self.owner_decisions
            ));
        }
        if self.owner_denials < MIN_OWNER_DENIALS {
            reasons.push(format!(
                "{} of {MIN_OWNER_DENIALS} owner denials",
                self.owner_denials
            ));
        }
        if self.power != Power::Ac {
            reasons.push(format!("power source: {}", self.power.label()));
        }
        reasons
    }
}

/// Count the owner decisions and denials of the log.
pub fn gate(records: &[DecisionRecord], power: Power) -> TrainingGate {
    let owner = records
        .iter()
        .filter(|record| record.entry.decided_by == DecidedBy::Owner);
    let (decisions, denials) = owner.fold((0, 0), |(all, denied), record| {
        (all + 1, denied + usize::from(record.entry.owner_denied()))
    });
    TrainingGate {
        owner_decisions: decisions,
        owner_denials: denials,
        power,
    }
}

// ---- Examples ----

/// One training example in the format of `tools/basemodel/train.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Example {
    /// The state that the broker sends ([`bouncer::state_text`]).
    pub state: String,
    pub question: String,
    pub instructions: String,
    /// 1 is yes, 0 is no. A teacher example has 0 here. The trainer replaces it.
    pub answer: u8,
    /// The target is the answer of the starting model, so the fine-tune keeps it.
    pub teacher: bool,
    /// `approval`, `denial`, `flagged_denial`, or `keep`.
    pub kind: &'static str,
    #[serde(skip)]
    command: String,
}

/// Counts of one conversion. No request data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExampleStats {
    pub lines: usize,
    pub owner_decisions: usize,
    pub owner_approvals: usize,
    pub owner_denials: usize,
    /// Owner decisions without a user request. They give no example.
    pub without_user_request: usize,
    /// Owner denials with a rule flag. The flag explains the denial, so they give no
    /// `task_match` example.
    pub flagged_denials: usize,
    /// Approvals of a state that the owner also denied. The denial wins.
    pub conflicts: usize,
    pub task_match_yes: usize,
    pub task_match_no: usize,
    pub destroy_yes: usize,
    pub keep: usize,
    /// Each denial example counts this many times.
    pub denial_weight: usize,
    pub train: usize,
    pub val: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExampleSet {
    pub train: Vec<Example>,
    pub val: Vec<Example>,
    pub stats: ExampleStats,
}

struct OwnerLine {
    state: String,
    command: String,
    allow: bool,
    flags: Vec<String>,
    has_rule: bool,
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("an export line has no text field `{name}`"))
}

fn texts(value: &Value, name: &str) -> Result<Vec<String>, String> {
    value
        .get(name)
        .and_then(Value::as_array)
        .and_then(|list| {
            list.iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| format!("an export line has no text list `{name}`"))
}

/// FNV-1a. Stable across runs and platforms.
fn fnv(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Convert a decision log export to training examples. Label mapping:
///
/// - Only owner decisions (`decided_by` = `owner`) with a user request give examples.
/// - An owner approval: `task_match` = yes for that request and command.
/// - An owner denial without a rule flag: `task_match` = no.
/// - An owner denial with a rule flag: no owner `task_match` example, because the flag
///   explains the denial. With the flag `data_loss`: `destroy` = yes.
/// - When the owner approved and denied the same state, the denial wins.
/// - Each state also gives teacher examples for each question without an owner label:
///   `task_match` (a flagged denial), `writes`, `remote`, `destroy`, and `rule_break`
///   (with an owner rule). The target is the answer of the starting model, so the
///   fine-tune does not move these answers.
/// - At most 3 identical examples. A denial example counts `task_match` approvals
///   divided by `task_match` denials times, from 2 to 10 (ADR 0009: a denial has more
///   weight).
/// - A hash of the command puts 20% of the commands in the validation part.
pub fn examples_from_export(jsonl: &str) -> Result<ExampleSet, String> {
    let questions: BTreeMap<&str, &str> = bouncer::questions().into_iter().collect();
    let question = |name: &str| questions.get(name).copied().unwrap_or_default().to_owned();
    let mut stats = ExampleStats::default();
    let mut lines = Vec::new();
    for (index, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        stats.lines += 1;
        let value: Value = serde_json::from_str(line)
            .map_err(|_| format!("export line {} is not JSON", index + 1))?;
        if value.get("schema").and_then(Value::as_str) != Some(EXPORT_SCHEMA) {
            return Err(format!(
                "export line {} is not in the format {EXPORT_SCHEMA}",
                index + 1
            ));
        }
        if text(&value, "decided_by")? != DecidedBy::Owner.as_str() {
            continue;
        }
        stats.owner_decisions += 1;
        let allow = match text(&value, "decision")? {
            "allow" => true,
            "deny" => false,
            _ => return Err(format!("export line {} has no valid decision", index + 1)),
        };
        if allow {
            stats.owner_approvals += 1;
        } else {
            stats.owner_denials += 1;
        }
        let user_request = text(&value, "user_request")?.trim();
        if user_request.is_empty() {
            stats.without_user_request += 1;
            continue;
        }
        let command = texts(&value, "command")?.join(" ");
        let instruction = text(&value, "instruction")?;
        let request = BouncerRequest {
            user_request: user_request.to_owned(),
            command: command.clone(),
            relative_dir: text(&value, "cwd_rel")?.to_owned(),
            purpose: text(&value, "purpose")?.to_owned(),
            env_names: texts(&value, "env_names")?,
            instruction: instruction.to_owned(),
        };
        lines.push(OwnerLine {
            state: bouncer::state_text(&request),
            command,
            allow,
            flags: texts(&value, "rule_flags")?,
            has_rule: !instruction.trim().is_empty(),
        });
    }

    let denied: BTreeSet<&str> = lines
        .iter()
        .filter(|line| !line.allow)
        .map(|line| line.state.as_str())
        .collect();
    let example = |line: &OwnerLine, name: &str, answer: u8, teacher, kind| Example {
        state: line.state.clone(),
        question: name.to_owned(),
        instructions: question(name),
        answer,
        teacher,
        kind,
        command: line.command.clone(),
    };
    let mut hard: Vec<Example> = Vec::new();
    for line in &lines {
        if line.allow {
            if denied.contains(line.state.as_str()) {
                stats.conflicts += 1;
            } else {
                hard.push(example(line, "task_match", 1, false, "approval"));
            }
        } else if line.flags.is_empty() {
            hard.push(example(line, "task_match", 0, false, "denial"));
        } else {
            stats.flagged_denials += 1;
            if line.flags.iter().any(|flag| flag == "data_loss") {
                hard.push(example(line, "destroy", 1, false, "flagged_denial"));
            }
        }
    }
    // At most MAX_COPIES identical examples.
    let mut copies: BTreeMap<(String, String, u8), usize> = BTreeMap::new();
    hard.retain(|example| {
        let count = copies
            .entry((
                example.state.clone(),
                example.question.clone(),
                example.answer,
            ))
            .or_insert(0);
        *count += 1;
        *count <= MAX_COPIES
    });
    // Teacher examples: one per state and question without an owner label.
    let labeled: BTreeSet<(&str, &str)> = hard
        .iter()
        .map(|example| (example.state.as_str(), example.question.as_str()))
        .collect();
    let mut keep = Vec::new();
    let mut seen = BTreeSet::new();
    for line in &lines {
        if !seen.insert(line.state.as_str()) {
            continue;
        }
        let mut names: Vec<&str> = vec!["task_match"];
        names.extend(KEEP_QUESTIONS);
        if line.has_rule {
            names.push("rule_break");
        }
        for name in names {
            if !labeled.contains(&(line.state.as_str(), name)) {
                keep.push(example(line, name, 0, true, "keep"));
            }
        }
    }
    stats.task_match_yes = hard.iter().filter(|e| e.kind == "approval").count();
    stats.task_match_no = hard.iter().filter(|e| e.kind == "denial").count();
    stats.destroy_yes = hard.iter().filter(|e| e.kind == "flagged_denial").count();
    stats.keep = keep.len();
    // The weight balances the `task_match` question, the one that the owner labels.
    stats.denial_weight = if stats.task_match_no == 0 {
        MIN_DENIAL_WEIGHT
    } else {
        ((stats.task_match_yes as f64 / stats.task_match_no as f64).round() as usize)
            .clamp(MIN_DENIAL_WEIGHT, MAX_DENIAL_WEIGHT)
    };
    let mut all = Vec::new();
    for example in hard {
        let times = if example.kind == "approval" {
            1
        } else {
            stats.denial_weight
        };
        all.extend(std::iter::repeat_n(example, times));
    }
    all.extend(keep);

    // Split by the command, so a command is in one part only.
    let is_val = |command: &str| fnv(command) % 100 < VAL_PERCENT;
    let (mut val, mut train): (Vec<Example>, Vec<Example>) = all
        .into_iter()
        .partition(|example| is_val(&example.command));
    if val.is_empty() {
        // Too few commands for the hash: the first command goes to validation.
        let Some(first) = train.iter().map(|e| e.command.clone()).min() else {
            return Err("The decision log gives no training example.".to_owned());
        };
        let (moved, rest): (Vec<Example>, Vec<Example>) =
            train.into_iter().partition(|e| e.command == first);
        val = moved;
        train = rest;
    }
    if train.is_empty() || val.is_empty() {
        return Err("The decision log gives too few distinct commands to train.".to_owned());
    }
    stats.train = train.len();
    stats.val = val.len();
    Ok(ExampleSet { train, val, stats })
}

// ---- Trainer ----

/// The trainer program and where its output goes.
#[derive(Debug, Clone)]
pub struct Trainer {
    pub program: PathBuf,
    /// Arguments before the job arguments, for example the script path.
    pub args: Vec<OsString>,
    /// Parent folder of the candidate folders. One new folder for each training.
    pub models_dir: PathBuf,
    /// The shipped base checkpoint. The heads start from it when it is present.
    pub init: Option<PathBuf>,
    /// The candidate name. Its version is `<name>+<hash8>`.
    pub name: String,
}

/// The `tools` folder that `scripts/build-app.sh` puts in the app bundle
/// (`Contents/Resources/tools`), when this program runs from `Contents/MacOS`.
fn bundled_tools() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let contents = exe.parent()?.parent()?;
    let tools = contents.join("Resources/tools");
    tools
        .join("finetune/local_train.py")
        .is_file()
        .then_some(tools)
}

fn laya_dir() -> PathBuf {
    match std::env::var_os("APASSY_LAYA_DIR").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => crate::paths::data_dir().join("laya"),
    }
}

impl Trainer {
    /// The Laya environment of `docs/operations/bouncer.md`: the Python of
    /// `$APASSY_LAYA_DIR/.venv`, the script `tools/finetune/local_train.py` in
    /// `APASSY_TOOLS_DIR`, else in the app bundle, else in `$APASSY_LAYA_DIR/tools`, and
    /// the base checkpoint in
    /// the order of `tools/basemodel/start.sh`.
    pub fn from_env() -> Result<Self, String> {
        let laya = laya_dir();
        let python = laya.join(".venv/bin/python");
        let tools = std::env::var_os("APASSY_TOOLS_DIR")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .or_else(bundled_tools)
            .unwrap_or_else(|| laya.join("tools"));
        let script = tools.join("finetune/local_train.py");
        if !python.is_file() {
            return Err(format!(
                "Training needs the Laya environment. {} is missing.",
                python.display()
            ));
        }
        if !script.is_file() {
            return Err(format!(
                "Training needs the trainer script. {} is missing. Build the app with scripts/build-app.sh, or set APASSY_TOOLS_DIR to the tools folder.",
                script.display()
            ));
        }
        let explicit = std::env::var_os("APASSY_BASE_MODEL")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let init = explicit
            .into_iter()
            .chain([
                laya.join("models/apassy-base-v1.safetensors"),
                PathBuf::from(
                    "/Applications/Apassy.app/Contents/Resources/models/apassy-base-v1.safetensors",
                ),
            ])
            .find(|path| path.is_file());
        Ok(Self {
            program: python,
            args: vec![script.into_os_string()],
            models_dir: laya.join("models/candidates"),
            init,
            name: LOCAL_MODEL_NAME.to_owned(),
        })
    }
}

/// Time limits of one training.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub time: Duration,
    pub power_every: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: TIME_LIMIT,
            power_every: POWER_CHECK_EVERY,
        }
    }
}

/// A finished training.
#[derive(Debug, Clone)]
pub struct TrainingReport {
    /// The candidate in shadow mode.
    pub candidate: CandidateRecord,
    /// Wall time of the trainer process.
    pub seconds: f64,
    pub stats: ExampleStats,
    /// `result.json` of the trainer.
    pub result: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrainingError {
    Locked,
    GateClosed(TrainingGate),
    Data(String),
    Start(String),
    /// The hard time limit stopped the trainer.
    TimedOut(Duration),
    /// The Mac left AC power. The trainer was stopped.
    OnBattery(Power),
    /// The owner stopped the trainer.
    Stopped,
    /// The trainer ended with an error. The text is the end of its log.
    Failed(String),
    /// The trainer result is not valid.
    Result(String),
    Register(String),
}

impl TrainingError {
    pub fn message(&self) -> String {
        match self {
            Self::Locked => "The vault is locked. Nothing was trained.".to_owned(),
            Self::GateClosed(gate) => format!(
                "Training did not start. The gate needs {MIN_OWNER_DECISIONS} owner decisions, {MIN_OWNER_DENIALS} owner denials, and AC power. Now: {}.",
                gate.reasons().join(", ")
            ),
            Self::Data(text) => format!("Training did not start. {text}"),
            Self::Start(text) => format!("The trainer did not start: {text}"),
            Self::TimedOut(limit) => format!(
                "Apassy stopped the training after {} minutes (the limit). No candidate was made.",
                limit.as_secs() / 60
            ),
            Self::OnBattery(power) => format!(
                "Apassy stopped the training: the power source is {}. No candidate was made.",
                power.label()
            ),
            Self::Stopped => "You stopped the training. No candidate was made.".to_owned(),
            Self::Failed(tail) => format!("The trainer failed. No candidate was made. {tail}"),
            Self::Result(text) => format!("The trainer result is not valid: {text}"),
            Self::Register(text) => format!("The candidate was not stored: {text}"),
        }
    }
}

/// Deletes a folder on drop.
struct RemoveOnDrop(Option<PathBuf>);

impl RemoveOnDrop {
    fn keep(&mut self) {
        self.0 = None;
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn private_dir(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn jsonl(examples: &[Example]) -> Vec<u8> {
    let mut out = Vec::new();
    for example in examples {
        if let Ok(line) = serde_json::to_vec(example) {
            out.extend_from_slice(&line);
            out.push(b'\n');
        }
    }
    out
}

/// Stop the process group of the trainer. The `kill` program avoids unsafe code.
fn stop_group(child: &mut Child) {
    let group = format!("-{}", child.id());
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

/// The last lines of the trainer log, short. The log has counts and losses only.
fn log_tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<String> = text
        .lines()
        .rev()
        .filter(|line| !line.trim().is_empty())
        .take(3)
        .map(|line| line.chars().take(MAX_LOG_LINE).collect())
        .collect();
    lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

/// Run the gate, the trainer, and the registration. `power` gives the power source.
/// The broker calls it again every `limits.power_every` during the training. `stop`
/// stops the trainer. `candidate_url` is the loopback address where the owner serves
/// the candidate.
pub fn train(
    vault: &SharedVault,
    trainer: &Trainer,
    candidate_url: &str,
    limits: Limits,
    power: &dyn Fn() -> Power,
    stop: &AtomicBool,
) -> Result<TrainingReport, TrainingError> {
    // The candidate goes to the vault file of the decisions, never to another vault
    // that the owner opens during the training (ADR 0013).
    let (export, vault_file) = {
        let guard = lock(vault);
        let vault = guard
            .as_ref()
            .filter(|vault| !vault.is_locked())
            .ok_or(TrainingError::Locked)?;
        let records = vault
            .decision_log()
            .map_err(|_| TrainingError::Data("The vault did not return the log.".to_owned()))?;
        let gate = gate(&records, power());
        if !gate.is_open() {
            return Err(TrainingError::GateClosed(gate));
        }
        let export = vault
            .export_decisions_jsonl()
            .map_err(|_| TrainingError::Data("The vault did not export the log.".to_owned()))?;
        (export, vault.path().to_path_buf())
    };
    let set = examples_from_export(&export).map_err(TrainingError::Data)?;
    drop(export);

    let io_error = |error: io::Error| TrainingError::Start(error.to_string());
    fs::create_dir_all(&trainer.models_dir).map_err(io_error)?;
    let now = learning::now();
    let out = trainer
        .models_dir
        .join(format!("candidate-{now}-{}", std::process::id()));
    private_dir(&out).map_err(io_error)?;
    // A failed training leaves nothing. A good one keeps the checkpoint and its files.
    let mut out_guard = RemoveOnDrop(Some(out.clone()));
    let data = out.join("data");
    private_dir(&data).map_err(io_error)?;
    // The examples have commands and user requests. They go when the trainer ends.
    let _data_guard = RemoveOnDrop(Some(data.clone()));
    write_private(&data.join("train.jsonl"), &jsonl(&set.train)).map_err(io_error)?;
    write_private(&data.join("val.jsonl"), &jsonl(&set.val)).map_err(io_error)?;
    let stats = serde_json::to_vec(&set.stats).unwrap_or_default();
    write_private(&data.join("stats.json"), &stats).map_err(io_error)?;
    drop(set.train);
    drop(set.val);

    let log_path = out.join("train.log");
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log_path)
        .map_err(io_error)?;
    let mut command = Command::new(&trainer.program);
    command
        .args(&trainer.args)
        .arg("--data")
        .arg(&data)
        .arg("--out")
        .arg(&out)
        .arg("--name")
        .arg(&trainer.name)
        .arg("--deadline")
        .arg(limits.time.as_secs().max(1).to_string());
    if let Some(init) = &trainer.init {
        command.arg("--init").arg(init);
    }
    command
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(io_error)?)
        .stderr(log)
        // Its own process group, so the stop reaches every child of the trainer.
        .process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().map_err(io_error)?;
    let mut power_checked = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                stop_group(&mut child);
                return Err(TrainingError::Failed(error.to_string()));
            }
        }
        if stop.load(Ordering::SeqCst) {
            stop_group(&mut child);
            return Err(TrainingError::Stopped);
        }
        if started.elapsed() >= limits.time {
            stop_group(&mut child);
            return Err(TrainingError::TimedOut(limits.time));
        }
        if power_checked.elapsed() >= limits.power_every {
            power_checked = Instant::now();
            let source = power();
            if source != Power::Ac {
                stop_group(&mut child);
                return Err(TrainingError::OnBattery(source));
            }
        }
        thread::sleep(POLL);
    };
    let seconds = started.elapsed().as_secs_f64();
    // A trainer child that stays in the group ends with the trainer.
    stop_group(&mut child);
    if !status.success() {
        return Err(TrainingError::Failed(log_tail(&log_path)));
    }
    let result = read_result(&out, &trainer.name)?;
    let _ = fs::remove_dir_all(out.join("encoder-cache"));

    let report = json!({
        "wall_seconds": (seconds * 10.0).round() / 10.0,
        "train_seconds": result.value.get("train_seconds"),
        "encoder_cache_seconds": result.value.get("encoder_cache_seconds"),
        "peak_mps_driver_gb": result.value.get("peak_mps_driver_gb"),
        "train_examples": result.value.get("train_examples"),
        "val_examples": result.value.get("val_examples"),
        "init": result.value.get("init_sha256"),
        "owner_decisions": set.stats.owner_decisions,
        "owner_denials": set.stats.owner_denials,
        "denial_weight": set.stats.denial_weight,
    })
    .to_string();
    let candidate = {
        let mut guard = lock(vault);
        let vault = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.path() == vault_file)
            .ok_or(TrainingError::Locked)?;
        vault
            .register_candidate(
                &NewCandidate {
                    version: result.version,
                    url: candidate_url.to_owned(),
                    checkpoint: result.checkpoint.display().to_string(),
                    checkpoint_sha256: result.sha256,
                    report,
                },
                learning::now(),
            )
            .map_err(|error| TrainingError::Register(error.to_string()))?
    };
    out_guard.keep();
    Ok(TrainingReport {
        candidate,
        seconds,
        stats: set.stats,
        result: result.value,
    })
}

struct TrainerResult {
    version: String,
    checkpoint: PathBuf,
    sha256: String,
    value: Value,
}

/// Read and check `result.json`: the version names the candidate and the first 8 hex
/// of its SHA-256, and the checkpoint is a file in the candidate folder.
fn read_result(out: &Path, name: &str) -> Result<TrainerResult, TrainingError> {
    let bad = |text: &str| TrainingError::Result(text.to_owned());
    let text = fs::read_to_string(out.join("result.json")).map_err(|_| bad("no result.json"))?;
    let value: Value = serde_json::from_str(&text).map_err(|_| bad("result.json is not JSON"))?;
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("no version"))?
        .to_owned();
    let sha256 = value
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("no sha256"))?
        .to_owned();
    let hex = sha256.len() == 64
        && sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !hex {
        return Err(bad("the sha256 is not 64 lowercase hex digits"));
    }
    if !valid_model_version(&version) || version != format!("{name}+{}", &sha256[..8]) {
        return Err(bad("the version does not match the name and the sha256"));
    }
    let checkpoint = value
        .get("checkpoint")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| bad("no checkpoint"))?;
    let checkpoint = fs::canonicalize(&checkpoint).map_err(|_| bad("no checkpoint file"))?;
    let folder = fs::canonicalize(out).map_err(|_| bad("no candidate folder"))?;
    if !checkpoint.starts_with(&folder) || !checkpoint.is_file() {
        return Err(bad("the checkpoint is not a file in the candidate folder"));
    }
    Ok(TrainerResult {
        version,
        checkpoint,
        sha256,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmset_output_names_the_power_source() {
        let ac = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1234)\t100%; charged; 0:00 remaining present: true\n";
        let battery = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1234)\t80%; discharging; 5:10 remaining present: true\n";
        let desktop = "Now drawing from 'AC Power'\n";
        assert_eq!(parse_pmset(ac), Power::Ac);
        assert_eq!(parse_pmset(desktop), Power::Ac);
        assert_eq!(parse_pmset(battery), Power::Battery);
        assert_eq!(
            parse_pmset("Now drawing from 'UPS Power'\n"),
            Power::Unknown
        );
        assert_eq!(parse_pmset(""), Power::Unknown);
        assert_eq!(parse_pmset("AC Power somewhere else"), Power::Unknown);
    }

    fn line(decision: &str, by: &str, command: &str, request: &str, flags: &[&str]) -> String {
        json!({
            "schema": EXPORT_SCHEMA,
            "time": "2026-09-26T10:00:00Z",
            "at": 1_790_416_800u64,
            "agent": "Claude Code",
            "user_request": request,
            "user_request_source": "agent",
            "command": command.split(' ').collect::<Vec<_>>(),
            "cwd_rel": ".",
            "purpose": "Do it.",
            "instruction": "",
            "env_names": ["DEMO_KEY"],
            "declaration": [null],
            "rule_flags": flags,
            "model_facts": {},
            "decision": decision,
            "decided_by": by,
            "remembered": false,
        })
        .to_string()
    }

    /// The label mapping of `docs/operations/fine-tune.md`.
    #[test]
    fn export_lines_map_to_owner_labels() {
        let lines = [
            line("allow", "owner", "npm test", "Run the tests.", &[]),
            line("allow", "owner", "npm test", "Run the tests.", &[]),
            line("allow", "owner", "npm run lint", "Lint the code.", &[]),
            line(
                "deny",
                "owner",
                "node scripts/grant-admin.js",
                "Run the tests.",
                &[],
            ),
            line("deny", "owner", "rm -rf data", "Clean up.", &["data_loss"]),
            line(
                "deny",
                "owner",
                "cat .env",
                "Show config.",
                &["secret_output"],
            ),
            line("allow", "model", "git status", "Show status.", &[]),
            line("deny", "rule", "psql -c drop", "Drop it.", &[]),
            line("deny", "no_answer", "npm publish", "Publish.", &[]),
            line("allow", "owner", "npm test", "", &[]),
            // Approved and denied: the denial wins.
            line("allow", "owner", "git push", "Push the branch.", &[]),
            line("deny", "owner", "git push", "Push the branch.", &[]),
        ]
        .join("\n");
        let set = examples_from_export(&lines).expect("examples");
        let stats = &set.stats;
        assert_eq!(stats.lines, 12);
        assert_eq!(
            stats.owner_decisions, 9,
            "model, rule, and no_answer lines are no labels"
        );
        assert_eq!(stats.owner_approvals, 5);
        assert_eq!(stats.owner_denials, 4);
        assert_eq!(stats.without_user_request, 1);
        assert_eq!(stats.flagged_denials, 2);
        assert_eq!(stats.conflicts, 1);
        assert_eq!(stats.task_match_yes, 3, "npm test twice, npm run lint");
        assert_eq!(stats.task_match_no, 2, "grant-admin, git push");
        assert_eq!(stats.destroy_yes, 1, "rm -rf data with data_loss");
        assert_eq!(
            stats.denial_weight, 2,
            "3 task_match approvals / 2 task_match denials, at least 2"
        );
        let all: Vec<&Example> = set.train.iter().chain(&set.val).collect();
        let hard = |question: &str, answer: u8, command: &str| {
            all.iter()
                .filter(|e| {
                    !e.teacher
                        && e.question == question
                        && e.answer == answer
                        && e.state.contains(&format!("`{command}`"))
                })
                .count()
        };
        assert_eq!(hard("task_match", 1, "npm test"), 2);
        assert_eq!(
            hard("task_match", 0, "node scripts/grant-admin.js"),
            2,
            "weight 2"
        );
        assert_eq!(hard("destroy", 1, "rm -rf data"), 2);
        assert_eq!(
            hard("task_match", 0, "cat .env"),
            0,
            "a flag explains the denial"
        );
        assert_eq!(hard("task_match", 1, "git push"), 0, "the denial wins");
        assert_eq!(hard("task_match", 0, "git push"), 2);
        assert_eq!(
            hard("task_match", 1, "git status"),
            0,
            "a model decision is no label"
        );
        // The state is the state of the broker.
        let state = &all
            .iter()
            .find(|e| e.state.contains("`npm run lint`"))
            .expect("lint")
            .state;
        assert_eq!(
            state,
            "User request: \"Lint the code.\". Shell command: `npm run lint`. Agent's stated purpose: Do it."
        );
        // Teacher examples keep each answer without an owner label: writes, remote, and
        // destroy, and task_match of a flagged denial.
        let keep = |command: &str| {
            all.iter()
                .filter(|e| e.teacher && e.state.contains(&format!("`{command}`")))
                .map(|e| e.question.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(keep("npm test"), vec!["writes", "remote", "destroy"]);
        assert_eq!(keep("rm -rf data"), vec!["task_match", "writes", "remote"]);
        assert_eq!(
            keep("cat .env"),
            vec!["task_match", "writes", "remote", "destroy"]
        );
        assert!(all.iter().all(|e| !e.instructions.is_empty()));
        // A command is in one part only.
        let train: BTreeSet<&str> = set.train.iter().map(|e| e.command.as_str()).collect();
        assert!(set.val.iter().all(|e| !train.contains(e.command.as_str())));
    }

    #[test]
    fn a_bad_export_gives_no_examples() {
        assert!(examples_from_export("not json").is_err());
        assert!(examples_from_export(r#"{"schema":"other"}"#).is_err());
        let only_model = line("allow", "model", "npm test", "Run the tests.", &[]);
        assert!(examples_from_export(&only_model).is_err());
    }

    #[test]
    fn many_approvals_give_a_heavier_denial() {
        let mut lines: Vec<String> = (0..40)
            .map(|n| {
                line(
                    "allow",
                    "owner",
                    &format!("npm run task{n}"),
                    "Run it.",
                    &[],
                )
            })
            .collect();
        lines.push(line("deny", "owner", "npm run evil", "Run it.", &[]));
        let set = examples_from_export(&lines.join("\n")).expect("examples");
        assert_eq!(set.stats.denial_weight, MAX_DENIAL_WEIGHT);
        let denials = set
            .train
            .iter()
            .chain(&set.val)
            .filter(|e| e.kind == "denial")
            .count();
        assert_eq!(denials, MAX_DENIAL_WEIGHT);
    }
}
