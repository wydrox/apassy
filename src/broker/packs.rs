//! Rule packs: knowledge about tools as versioned data (ADR 0009, ADR 0010).
//!
//! A pack is a JSON file for one tool or for a group of small tools. It has
//! declarative matchers for the program, the subcommand, options, and arguments.
//! The command analysis in [`super::shell_risk`] keeps the shell parser, the secret
//! flow, and the general rules. It asks the packs about each program.
//!
//! - Built-in packs are the files in `packs/`. The binary embeds them, so only an
//!   app release changes them. A built-in pack can add flags, mark a command as known
//!   safe, give a program a role for the general rules, name known provider hosts,
//!   and make an exception to a general rule.
//! - Local packs are owner files. Their schema has flag rules only. A local pack
//!   can add a flag. It cannot mark a command as safe, remove a flag, or replace a
//!   built-in pack. The analysis joins the flags of all packs.
//!
//! If a local pack does not load, every analysis adds the flag
//! [`LOAD_ERROR_FLAG`]. Then every run waits for the owner.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, PoisonError, RwLock};

use serde::Deserialize;
use serde_json::Value;

use super::shell_risk;

/// The pack format that this version of Apassy reads.
pub const SCHEMA_VERSION: u64 = 1;

/// The flag of every analysis when a local pack does not load.
pub const LOAD_ERROR_FLAG: &str = "rule_pack_error";

/// The directory of local packs. The default is [`default_local_dir`].
pub const PACKS_DIR_ENV: &str = "APASSY_PACKS_DIR";

/// Flags that a rule can add. `ask_owner` has no other meaning: the owner decides.
/// `hook_channel`: the command names the host hook program, the host settings, or a
/// host transcript (goal item B6).
pub const RULE_FLAGS: &[&str] = &[
    "secret_output",
    "data_loss",
    "production",
    "real_recipient",
    "remote_code",
    "remote_access",
    "system_change",
    "new_dependency",
    "privilege",
    "hook_channel",
    "ask_owner",
];

/// Fields that only a built-in pack can have. Each one can make the analysis less strict.
const BUILTIN_ONLY_FIELDS: &[&str] = &["safe", "exemptions", "roles", "known_hosts"];

/// The largest local pack file.
const MAX_LOCAL_PACK_BYTES: u64 = 1024 * 1024;

/// Built-in packs, embedded at build time. Only an app release changes them.
const BUILTIN: &[(&str, &str)] = &[
    ("aws.json", include_str!("../../packs/aws.json")),
    ("cargo.json", include_str!("../../packs/cargo.json")),
    ("cloud.json", include_str!("../../packs/cloud.json")),
    ("databases.json", include_str!("../../packs/databases.json")),
    ("docker.json", include_str!("../../packs/docker.json")),
    ("encoding.json", include_str!("../../packs/encoding.json")),
    (
        "file-tools.json",
        include_str!("../../packs/file-tools.json"),
    ),
    ("gh.json", include_str!("../../packs/gh.json")),
    ("git.json", include_str!("../../packs/git.json")),
    ("go.json", include_str!("../../packs/go.json")),
    ("http.json", include_str!("../../packs/http.json")),
    ("js-tools.json", include_str!("../../packs/js-tools.json")),
    (
        "kubernetes.json",
        include_str!("../../packs/kubernetes.json"),
    ),
    ("macos.json", include_str!("../../packs/macos.json")),
    ("make.json", include_str!("../../packs/make.json")),
    ("netlify.json", include_str!("../../packs/netlify.json")),
    ("node.json", include_str!("../../packs/node.json")),
    ("npm.json", include_str!("../../packs/npm.json")),
    ("prisma.json", include_str!("../../packs/prisma.json")),
    ("python.json", include_str!("../../packs/python.json")),
    ("remote.json", include_str!("../../packs/remote.json")),
    ("scripting.json", include_str!("../../packs/scripting.json")),
    ("shell.json", include_str!("../../packs/shell.json")),
    ("supabase.json", include_str!("../../packs/supabase.json")),
    ("system.json", include_str!("../../packs/system.json")),
    ("terraform.json", include_str!("../../packs/terraform.json")),
    ("vercel.json", include_str!("../../packs/vercel.json")),
];

/// File names of the built-in packs in `packs/`.
pub fn builtin_pack_files() -> Vec<&'static str> {
    BUILTIN.iter().map(|(name, _)| *name).collect()
}

// ---- Errors and pack information ----

/// A pack that does not load. `source` is the file name or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackError {
    pub source: String,
    pub message: String,
}

impl PackError {
    fn new(source: &str, message: impl Into<String>) -> Self {
        Self {
            source: source.to_owned(),
            message: message.into(),
        }
    }
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.source, self.message)
    }
}

impl std::error::Error for PackError {}

/// Where a pack comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    BuiltIn,
    Local(String),
}

/// A loaded pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackInfo {
    pub tool: String,
    pub pack_version: u64,
    pub origin: Origin,
    pub rules: usize,
}

// ---- Schema ----

/// What a program does. The general rules of the analysis use roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Role {
    /// Prints or copies its input or its files.
    Output,
    /// Encodes or compresses data.
    Encoder,
    /// Moves data over the network.
    Network,
    /// Sends HTTP requests. The analysis checks auth headers, uploads, and recipients.
    HttpClient,
    /// Runs a here-document as code.
    HeredocCode,
    /// Runs a here-document as SQL.
    HeredocSql,
    /// Writes its input to a file.
    FileWriter,
    /// Runs a script file. The name of the script can tell about data loss.
    ScriptRunner,
    /// Runs a named task or package script: the argument after `run` or `run-script`,
    /// or else the first argument. The name of the task can tell about data loss.
    TaskRunner,
    /// Prints usage and stops for `--help`, `--version`, `help`, or a lone `-h`.
    Usage,
    /// The data-loss checks ignore dry-run options for this program.
    NoDryRun,
}

/// A general rule that a built-in pack can make an exception to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Check {
    /// A secret file as an argument is secret output.
    SecretFileArgument,
    /// A production word in an argument is a production target.
    ProductionWord,
}

/// The general rule "a dry run does not act" for a flag rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DryRun {
    /// The rule does not apply with `--dry-run` or `--dryrun`.
    Skip,
    /// The rule also does not apply with `-n`, except for a program with the role
    /// `no_dry_run`. For such a program the rule applies to a dry run too.
    SkipWithN,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SqlCheck {
    /// The SQL argument changes data, schema, or access.
    Writes,
    /// The SQL argument is a read statement only.
    Reads,
    /// An argument that is not an option, with a space in it, is SQL that changes data,
    /// schema, or access. For clients that take SQL as a plain argument, such as
    /// `sqlite3 app.db "DELETE FROM users"`.
    AnyArgWrites,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinPack {
    #[allow(dead_code)]
    schema_version: u64,
    pack_version: u64,
    tool: String,
    description: String,
    programs: Vec<String>,
    #[serde(default)]
    roles: BTreeMap<Role, Vec<String>>,
    #[serde(default)]
    known_hosts: Vec<String>,
    #[serde(default)]
    rules: Vec<FlagRule>,
    #[serde(default)]
    exemptions: Vec<Exemption>,
    #[serde(default)]
    safe: Vec<SafeRule>,
}

/// The schema of a local pack: flag rules only.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalPack {
    #[allow(dead_code)]
    schema_version: u64,
    pack_version: u64,
    tool: String,
    description: String,
    programs: Vec<String>,
    rules: Vec<FlagRule>,
}

/// A rule that adds a flag when its matcher matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlagRule {
    id: String,
    flag: String,
    #[serde(default)]
    dry_run: Option<DryRun>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    #[serde(default)]
    when: Matcher,
}

/// An exception to a general rule. Built-in packs only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exemption {
    id: String,
    check: Check,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    #[serde(default)]
    when: Matcher,
}

/// A known safe command. Built-in packs only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SafeRule {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    #[serde(default)]
    when: Matcher,
}

/// Conditions on one command. All present conditions must hold. A list means "one of".
/// Arguments are in lowercase unless a condition says "as written".
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Matcher {
    /// The program after wrappers such as `sudo`, `npx`, and `env`.
    program: Option<Vec<String>>,
    /// The first word of the command, before wrappers.
    raw_program: Option<Vec<String>>,
    /// The command runs a package with `npx`, `bunx`, `pnpm dlx`, or `yarn dlx`.
    package_runner: Option<bool>,
    /// The package name: the program before `@`.
    package: Option<Vec<String>>,
    /// The program word as written contains one of these texts.
    program_word_contains: Option<Vec<String>>,
    /// The first argument. A missing argument is the empty text.
    subcommand: Option<Vec<String>>,
    /// The second argument. A missing argument is the empty text.
    action: Option<Vec<String>>,
    /// A package script: the word after `run` or `run-script`, else the first argument.
    script: Option<ScriptMatch>,
    arg_count: Option<usize>,
    /// Every argument starts with `-`.
    only_options: Option<bool>,
    any_arg: Option<Vec<String>>,
    any_arg_starts: Option<Vec<String>>,
    any_arg_contains: Option<Vec<String>>,
    /// The arguments, joined with spaces, start with one of these texts.
    args_start: Option<Vec<String>>,
    /// The arguments, joined with spaces, contain one of these texts.
    args_contain: Option<Vec<String>>,
    /// The program and the arguments, joined with spaces, contain one of these texts.
    command_contains: Option<Vec<String>>,
    /// As `command_contains`, as written.
    command_contains_exact: Option<Vec<String>>,
    /// A word of the command as written, wrappers included, contains one of these texts.
    word_contains: Option<Vec<String>>,
    /// All text of the segment contains one of these texts: the `NAME=value` prefixes,
    /// the words as written, the redirect targets, and the here-document, in lowercase.
    segment_contains: Option<Vec<String>>,
    /// A word of the segment text ends with one of these texts. Words split at spaces,
    /// quotes, `=`, and shell operators. A trailing `/` does not count.
    segment_word_ends: Option<Vec<String>>,
    /// An option and the next argument.
    option_value: Option<OptionValue>,
    /// A group of short options, such as `-rf`, contains this letter.
    short_option_letter: Option<String>,
    /// An option word, short or long, contains this letter.
    option_letter: Option<String>,
    /// Arguments that do not start with `-`.
    operands: Option<OperandMatch>,
    /// A branch that `git push` updates: the part after `:` of each refspec.
    push_target: Option<Vec<String>>,
    /// There is at least one URL, and every URL host is one of these hosts.
    url_hosts_in: Option<Vec<String>>,
    /// A GET request without a body or an upload, to known provider hosts only.
    known_host_read: Option<bool>,
    /// A word of the command refers to a secret.
    refs_secret: Option<bool>,
    /// An argument after the program refers to a secret.
    arg_refs_secret: Option<bool>,
    /// An argument is a secret file, such as `.env` or an SSH key.
    secret_file_arg: Option<bool>,
    /// As `secret_file_arg`, as written.
    secret_file_arg_as_written: Option<bool>,
    /// An argument is a system path, such as `/etc/hosts`.
    system_path_arg: Option<bool>,
    /// Code in the command reads the environment and prints, writes, or sends it.
    inline_code_leaks: Option<bool>,
    /// The SQL argument (`-c`, `--command`, `-e`, `--eval`, or after `query`).
    sql: Option<SqlCheck>,
    any_of: Option<Vec<Matcher>>,
    not: Option<Box<Matcher>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptMatch {
    /// The script name before the first `:`.
    base: Vec<String>,
    /// Texts that the full script name must not contain.
    #[serde(default)]
    not_contains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionValue {
    option: Vec<String>,
    value: Option<Vec<String>>,
    not_value: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperandMatch {
    /// Keep the case of the operands.
    #[serde(default)]
    as_written: bool,
    /// Text to remove from the start of each operand, repeatedly.
    trim_start: Option<String>,
    /// Text to remove from the end of each operand, repeatedly.
    trim_end: Option<String>,
    count: Option<usize>,
    min: Option<usize>,
    /// One operand matches one pattern.
    any: Option<Vec<TextPattern>>,
    /// There is an operand, and each operand matches a pattern.
    all: Option<Vec<TextPattern>>,
    /// `all` also holds when there is no operand.
    #[serde(default)]
    allow_none: bool,
    at: Option<OperandAt>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperandAt {
    index: usize,
    #[serde(rename = "in")]
    in_list: Option<Vec<String>>,
    not_in: Option<Vec<String>>,
    /// The operand starts with one of these texts.
    starts: Option<Vec<String>>,
}

/// A text pattern. All present conditions must hold.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextPattern {
    equals: Option<Vec<String>>,
    starts: Option<Vec<String>>,
    ends: Option<Vec<String>>,
    contains: Option<Vec<String>>,
    /// Length in bytes.
    max_len: Option<usize>,
    /// A path in a temporary folder such as `/tmp/`.
    temp_path: Option<bool>,
}

// ---- The command that the matchers see ----

/// One simple command of a pipeline, prepared for the matchers.
pub(crate) struct Command<'a> {
    /// The words as written, wrappers included.
    pub(crate) words: &'a [String],
    /// The words after wrappers. Never empty.
    pub(crate) argv: &'a [String],
    /// Base name of the program after wrappers, in lowercase.
    pub(crate) program: String,
    /// Base name of the first word, in lowercase.
    pub(crate) raw_program: String,
    /// Arguments after the program, in lowercase.
    pub(crate) args: Vec<String>,
    pub(crate) args_joined: String,
    /// Program and arguments as written, joined with spaces.
    pub(crate) joined: String,
    pub(crate) joined_lower: String,
    /// All text of the segment in lowercase. See `segment_contains`.
    pub(crate) segment_text: String,
    /// A word refers to a secret.
    pub(crate) secret: bool,
    pub(crate) secret_names: &'a [String],
    pub(crate) known_hosts: &'a [String],
}

impl Command<'_> {
    fn subcommand(&self) -> &str {
        self.args.first().map(String::as_str).unwrap_or_default()
    }

    fn action(&self) -> &str {
        self.args.get(1).map(String::as_str).unwrap_or_default()
    }

    fn script(&self) -> &str {
        match self.subcommand() {
            "run" | "run-script" => self.action(),
            sub => sub,
        }
    }

    fn package(&self) -> &str {
        self.program.split('@').next().unwrap_or(&self.program)
    }
}

fn has(list: &[String], text: &str) -> bool {
    list.iter().any(|item| item == text)
}

/// A condition that is absent holds.
fn holds<T>(condition: &Option<T>, test: impl FnOnce(&T) -> bool) -> bool {
    condition.as_ref().is_none_or(test)
}

impl Matcher {
    fn matches(&self, cmd: &Command<'_>) -> bool {
        holds(&self.program, |list| has(list, &cmd.program))
            && holds(&self.raw_program, |list| has(list, &cmd.raw_program))
            && holds(&self.package_runner, |want| {
                shell_risk::is_package_runner(cmd.words) == *want
            })
            && holds(&self.package, |list| has(list, cmd.package()))
            && holds(&self.program_word_contains, |list| {
                list.iter().any(|text| cmd.argv[0].contains(text.as_str()))
            })
            && holds(&self.subcommand, |list| has(list, cmd.subcommand()))
            && holds(&self.action, |list| has(list, cmd.action()))
            && holds(&self.script, |script| script.matches(cmd.script()))
            && holds(&self.arg_count, |count| cmd.args.len() == *count)
            && holds(&self.only_options, |want| {
                cmd.args.iter().all(|arg| arg.starts_with('-')) == *want
            })
            && holds(&self.any_arg, |list| {
                cmd.args.iter().any(|arg| has(list, arg))
            })
            && holds(&self.any_arg_starts, |list| {
                cmd.args
                    .iter()
                    .any(|arg| list.iter().any(|text| arg.starts_with(text.as_str())))
            })
            && holds(&self.any_arg_contains, |list| {
                cmd.args
                    .iter()
                    .any(|arg| list.iter().any(|text| arg.contains(text.as_str())))
            })
            && holds(&self.args_start, |list| {
                list.iter()
                    .any(|text| cmd.args_joined.starts_with(text.as_str()))
            })
            && holds(&self.args_contain, |list| {
                list.iter()
                    .any(|text| cmd.args_joined.contains(text.as_str()))
            })
            && holds(&self.command_contains, |list| {
                list.iter()
                    .any(|text| cmd.joined_lower.contains(text.as_str()))
            })
            && holds(&self.command_contains_exact, |list| {
                list.iter().any(|text| cmd.joined.contains(text.as_str()))
            })
            && holds(&self.word_contains, |list| {
                cmd.words.iter().any(|word| {
                    let word = word.to_lowercase();
                    list.iter().any(|text| word.contains(text.as_str()))
                })
            })
            && holds(&self.segment_contains, |list| {
                list.iter()
                    .any(|text| cmd.segment_text.contains(text.as_str()))
            })
            && holds(&self.segment_word_ends, |list| {
                shell_risk::text_words(&cmd.segment_text)
                    .any(|word| list.iter().any(|end| word.ends_with(end.as_str())))
            })
            && holds(&self.option_value, |option| option.matches(&cmd.args))
            && holds(&self.short_option_letter, |letter| {
                cmd.args.iter().any(|arg| {
                    arg.starts_with('-') && !arg.starts_with("--") && arg.contains(letter.as_str())
                })
            })
            && holds(&self.option_letter, |letter| {
                cmd.args
                    .iter()
                    .any(|arg| arg.starts_with('-') && arg.contains(letter.as_str()))
            })
            && holds(&self.operands, |operands| operands.matches(cmd))
            && holds(&self.push_target, |list| {
                shell_risk::push_targets(&cmd.args)
                    .iter()
                    .any(|target| has(list, target))
            })
            && holds(&self.url_hosts_in, |list| {
                let hosts = shell_risk::url_hosts(cmd.argv);
                !hosts.is_empty() && hosts.iter().all(|host| has(list, host))
            })
            && holds(&self.known_host_read, |want| {
                shell_risk::is_authenticated_read(cmd.argv, cmd.known_hosts) == *want
            })
            && holds(&self.refs_secret, |want| cmd.secret == *want)
            && holds(&self.arg_refs_secret, |want| {
                cmd.argv
                    .iter()
                    .skip(1)
                    .any(|arg| shell_risk::refs_secret(arg, cmd.secret_names))
                    == *want
            })
            && holds(&self.secret_file_arg, |want| {
                cmd.args.iter().any(|arg| shell_risk::is_secret_file(arg)) == *want
            })
            && holds(&self.secret_file_arg_as_written, |want| {
                cmd.argv
                    .iter()
                    .skip(1)
                    .any(|arg| shell_risk::is_secret_file(arg))
                    == *want
            })
            && holds(&self.system_path_arg, |want| {
                cmd.argv
                    .iter()
                    .skip(1)
                    .any(|arg| shell_risk::is_system_path(arg))
                    == *want
            })
            && holds(&self.inline_code_leaks, |want| {
                shell_risk::inline_code_leaks(&cmd.joined, cmd.secret_names) == *want
            })
            && holds(&self.sql, |check| match check {
                SqlCheck::Writes => shell_risk::sql_argument(cmd.argv)
                    .is_some_and(|sql| shell_risk::sql_writes(&sql)),
                SqlCheck::Reads => shell_risk::sql_argument(cmd.argv)
                    .is_some_and(|sql| shell_risk::sql_reads(&sql)),
                SqlCheck::AnyArgWrites => cmd.argv.iter().skip(1).any(|arg| {
                    !arg.starts_with('-') && arg.contains(' ') && shell_risk::sql_writes(arg)
                }),
            })
            && holds(&self.any_of, |list| {
                list.iter().any(|matcher| matcher.matches(cmd))
            })
            && holds(&self.not, |matcher| !matcher.matches(cmd))
    }
}

impl ScriptMatch {
    fn matches(&self, name: &str) -> bool {
        let base = name.split(':').next().unwrap_or(name);
        has(&self.base, base)
            && !self
                .not_contains
                .iter()
                .any(|text| name.contains(text.as_str()))
    }
}

impl OptionValue {
    fn matches(&self, args: &[String]) -> bool {
        args.windows(2).any(|pair| {
            has(&self.option, &pair[0])
                && holds(&self.value, |list| has(list, &pair[1]))
                && holds(&self.not_value, |list| !has(list, &pair[1]))
        })
    }
}

impl OperandMatch {
    fn matches(&self, cmd: &Command<'_>) -> bool {
        let source: &[String] = if self.as_written {
            &cmd.argv[1..]
        } else {
            &cmd.args
        };
        let operands: Vec<&str> = source
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .map(|arg| {
                let mut text = arg.as_str();
                if let Some(prefix) = &self.trim_start {
                    text = text.trim_start_matches(prefix.as_str());
                }
                if let Some(suffix) = &self.trim_end {
                    text = text.trim_end_matches(suffix.as_str());
                }
                text
            })
            .collect();
        let matches_any = |text: &str, patterns: &[TextPattern]| {
            patterns.iter().any(|pattern| pattern.matches(text))
        };
        holds(&self.count, |count| operands.len() == *count)
            && holds(&self.min, |min| operands.len() >= *min)
            && holds(&self.any, |patterns| {
                operands.iter().any(|text| matches_any(text, patterns))
            })
            && holds(&self.all, |patterns| {
                (self.allow_none || !operands.is_empty())
                    && operands.iter().all(|text| matches_any(text, patterns))
            })
            && holds(&self.at, |at| {
                operands.get(at.index).is_some_and(|text| {
                    holds(&at.in_list, |list| has(list, text))
                        && holds(&at.not_in, |list| !has(list, text))
                        && holds(&at.starts, |list| {
                            list.iter().any(|prefix| text.starts_with(prefix.as_str()))
                        })
                })
            })
    }
}

impl TextPattern {
    fn matches(&self, text: &str) -> bool {
        holds(&self.equals, |list| has(list, text))
            && holds(&self.starts, |list| {
                list.iter().any(|prefix| text.starts_with(prefix.as_str()))
            })
            && holds(&self.ends, |list| {
                list.iter().any(|suffix| text.ends_with(suffix.as_str()))
            })
            && holds(&self.contains, |list| {
                list.iter().any(|part| text.contains(part.as_str()))
            })
            && holds(&self.max_len, |max| text.len() <= *max)
            && holds(&self.temp_path, |want| {
                shell_risk::is_temp_path(text) == *want
            })
    }
}

// ---- Validation ----

/// The programs that a pack may name. `*` means every program.
struct Scope<'a> {
    programs: &'a [String],
    any_program: bool,
}

fn check_list(
    list: &[String],
    field: &str,
    lowercase: bool,
    allow_empty_text: bool,
) -> Result<(), String> {
    if list.is_empty() {
        return Err(format!("`{field}` is an empty list"));
    }
    for item in list {
        if item.is_empty() && !allow_empty_text {
            return Err(format!("`{field}` has an empty text"));
        }
        if lowercase && item.to_lowercase() != *item {
            return Err(format!(
                "`{field}` has `{item}`: the analysis compares lowercase text, so use lowercase"
            ));
        }
    }
    Ok(())
}

fn check_programs(list: &[String], field: &str, scope: &Scope<'_>) -> Result<(), String> {
    check_list(list, field, true, false)?;
    if scope.any_program {
        return Ok(());
    }
    match list.iter().find(|program| !has(scope.programs, program)) {
        Some(program) => Err(format!(
            "`{field}` names `{program}`, which is not in the programs of the pack"
        )),
        None => Ok(()),
    }
}

fn check_letter(letter: &str, field: &str) -> Result<(), String> {
    let mut chars = letter.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii_lowercase() => Ok(()),
        _ => Err(format!("`{field}` must be one lowercase letter")),
    }
}

impl TextPattern {
    fn validate(&self, lowercase: bool) -> Result<(), String> {
        if *self == Self::default() {
            return Err("a text pattern has no condition".to_owned());
        }
        for (field, list) in [
            ("equals", &self.equals),
            ("starts", &self.starts),
            ("ends", &self.ends),
            ("contains", &self.contains),
        ] {
            if let Some(list) = list {
                check_list(list, field, lowercase, field == "equals")?;
            }
        }
        Ok(())
    }
}

impl Matcher {
    fn validate(&self, scope: &Scope<'_>) -> Result<(), String> {
        if let Some(list) = &self.program {
            check_programs(list, "program", scope)?;
        }
        if let Some(list) = &self.raw_program {
            check_programs(list, "raw_program", scope)?;
        }
        for (field, list, allow_empty_text) in [
            ("package", &self.package, false),
            ("subcommand", &self.subcommand, true),
            ("action", &self.action, true),
            ("any_arg", &self.any_arg, false),
            ("any_arg_starts", &self.any_arg_starts, false),
            ("any_arg_contains", &self.any_arg_contains, false),
            ("args_start", &self.args_start, false),
            ("args_contain", &self.args_contain, false),
            ("command_contains", &self.command_contains, false),
            ("word_contains", &self.word_contains, false),
            ("segment_contains", &self.segment_contains, false),
            ("segment_word_ends", &self.segment_word_ends, false),
            ("push_target", &self.push_target, false),
            ("url_hosts_in", &self.url_hosts_in, false),
        ] {
            if let Some(list) = list {
                check_list(list, field, true, allow_empty_text)?;
            }
        }
        for (field, list) in [
            ("program_word_contains", &self.program_word_contains),
            ("command_contains_exact", &self.command_contains_exact),
        ] {
            if let Some(list) = list {
                check_list(list, field, false, false)?;
            }
        }
        if let Some(script) = &self.script {
            check_list(&script.base, "script.base", true, false)?;
            if !script.not_contains.is_empty() {
                check_list(&script.not_contains, "script.not_contains", true, false)?;
            }
        }
        if let Some(option) = &self.option_value {
            check_list(&option.option, "option_value.option", true, false)?;
            match (&option.value, &option.not_value) {
                (Some(list), None) => check_list(list, "option_value.value", true, false)?,
                (None, Some(list)) => check_list(list, "option_value.not_value", true, false)?,
                _ => {
                    return Err(
                        "`option_value` needs exactly one of `value` and `not_value`".to_owned(),
                    );
                }
            }
        }
        if let Some(letter) = &self.short_option_letter {
            check_letter(letter, "short_option_letter")?;
        }
        if let Some(letter) = &self.option_letter {
            check_letter(letter, "option_letter")?;
        }
        if let Some(operands) = &self.operands {
            operands.validate()?;
        }
        if let Some(list) = &self.any_of {
            if list.is_empty() {
                return Err("`any_of` is an empty list".to_owned());
            }
            for matcher in list {
                matcher.validate_nested(scope, "any_of")?;
            }
        }
        if let Some(matcher) = &self.not {
            matcher.validate_nested(scope, "not")?;
        }
        Ok(())
    }

    fn validate_nested(&self, scope: &Scope<'_>, field: &str) -> Result<(), String> {
        if *self == Self::default() {
            return Err(format!("`{field}` has a matcher without a condition"));
        }
        self.validate(scope)
    }
}

impl OperandMatch {
    fn validate(&self) -> Result<(), String> {
        if self.count.is_none()
            && self.min.is_none()
            && self.any.is_none()
            && self.all.is_none()
            && self.at.is_none()
        {
            return Err("`operands` needs `count`, `min`, `any`, `all`, or `at`".to_owned());
        }
        let lowercase = !self.as_written;
        for text in [&self.trim_start, &self.trim_end].into_iter().flatten() {
            if text.is_empty() {
                return Err("`operands` has an empty trim text".to_owned());
            }
        }
        for patterns in [&self.any, &self.all].into_iter().flatten() {
            if patterns.is_empty() {
                return Err("`operands` has an empty pattern list".to_owned());
            }
            for pattern in patterns {
                pattern.validate(lowercase)?;
            }
        }
        if self.allow_none && self.all.is_none() {
            return Err("`allow_none` needs `all`".to_owned());
        }
        if let Some(at) = &self.at {
            match (&at.in_list, &at.not_in, &at.starts) {
                (Some(list), None, None) | (None, Some(list), None) | (None, None, Some(list)) => {
                    check_list(list, "operands.at", lowercase, false)?;
                }
                _ => {
                    return Err(
                        "`operands.at` needs exactly one of `in`, `not_in`, and `starts`"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Parse a pack file and check its schema version before the schema.
fn parse(source: &str, text: &str) -> Result<Value, PackError> {
    let value: Value = serde_json::from_str(text)
        .map_err(|error| PackError::new(source, format!("not valid JSON: {error}")))?;
    check_header(source, &value)?;
    Ok(value)
}

fn check_header(source: &str, value: &Value) -> Result<(), PackError> {
    let Some(object) = value.as_object() else {
        return Err(PackError::new(source, "a pack is a JSON object"));
    };
    match object.get("schema_version").and_then(Value::as_u64) {
        Some(SCHEMA_VERSION) => {}
        Some(other) => {
            return Err(PackError::new(
                source,
                format!(
                    "schema_version {other} is not supported; this Apassy reads version {SCHEMA_VERSION}"
                ),
            ));
        }
        None => {
            return Err(PackError::new(
                source,
                "`schema_version` is missing or not a number",
            ));
        }
    }
    Ok(())
}

fn check_tool_name(tool: &str) -> Result<(), String> {
    let valid = !tool.is_empty()
        && tool.len() <= 64
        && tool
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "tool `{tool}`: use 1 to 64 lowercase letters, digits, `-`, or `_`"
        ))
    }
}

/// The programs of a pack. `*` alone means every program.
fn check_pack_programs(programs: &[String]) -> Result<bool, String> {
    if programs.len() == 1 && programs[0] == "*" {
        return Ok(true);
    }
    check_list(programs, "programs", true, false)?;
    if programs.iter().any(|program| program == "*") {
        return Err("`*` must be the only program".to_owned());
    }
    let unique: BTreeSet<&String> = programs.iter().collect();
    if unique.len() != programs.len() {
        return Err("`programs` names a program twice".to_owned());
    }
    Ok(false)
}

fn check_ids<'a>(ids: impl Iterator<Item = &'a str>, kind: &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for id in ids {
        check_tool_name(id)
            .map_err(|_| format!("{kind} id `{id}`: use lowercase letters, digits, `-`, or `_`"))?;
        if !seen.insert(id) {
            return Err(format!("{kind} id `{id}` is used twice"));
        }
    }
    Ok(())
}

fn check_rule(rule: &FlagRule, scope: &Scope<'_>) -> Result<(), String> {
    if !RULE_FLAGS.contains(&rule.flag.as_str()) {
        return Err(format!(
            "rule `{}`: flag `{}` is not one of {}",
            rule.id,
            rule.flag,
            RULE_FLAGS.join(", ")
        ));
    }
    rule.when
        .validate(scope)
        .map_err(|message| format!("rule `{}`: {message}", rule.id))
}

// ---- Rule sets ----

/// A rule with the programs that it applies to.
#[derive(Debug, Clone)]
struct Compiled<T> {
    tool: String,
    item: T,
}

/// All loaded packs. The analysis uses one rule set.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    packs: Vec<PackInfo>,
    rules: Vec<Compiled<FlagRule>>,
    exemptions: Vec<Compiled<Exemption>>,
    safe: Vec<Compiled<SafeRule>>,
    roles: BTreeMap<Role, BTreeSet<String>>,
    known_hosts: Vec<String>,
    load_error: Option<String>,
}

/// A rule without `program` or `raw_program` applies to the programs of its pack.
fn scoped(mut when: Matcher, programs: &[String], any_program: bool) -> Matcher {
    if when.program.is_none() && when.raw_program.is_none() && !any_program {
        when.program = Some(programs.to_vec());
    }
    when
}

impl RuleSet {
    /// The built-in packs.
    pub fn builtin() -> Result<Self, PackError> {
        let mut set = Self::default();
        for (name, text) in BUILTIN {
            set.add_builtin(name, text)?;
        }
        Ok(set)
    }

    /// A rule set that failed to load. Every analysis adds [`LOAD_ERROR_FLAG`].
    pub fn failed(error: &PackError) -> Self {
        Self::default().fail_closed(error)
    }

    /// Keep the rules, and add [`LOAD_ERROR_FLAG`] to every analysis.
    pub fn fail_closed(mut self, error: &PackError) -> Self {
        self.load_error = Some(error.to_string());
        self
    }

    /// The loaded packs.
    pub fn packs(&self) -> &[PackInfo] {
        &self.packs
    }

    /// The reason why a pack did not load. Then every analysis asks the owner.
    pub fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    /// Checks that built-in and local packs share. Gives true for a pack of every program.
    fn check_common(
        &self,
        source: &str,
        tool: &str,
        pack_version: u64,
        description: &str,
        programs: &[String],
        rules: &[FlagRule],
    ) -> Result<bool, PackError> {
        let fail = |message: String| PackError::new(source, message);
        check_tool_name(tool).map_err(fail)?;
        if let Some(existing) = self.packs.iter().find(|pack| pack.tool == tool) {
            return Err(fail(match existing.origin {
                Origin::BuiltIn => format!(
                    "tool `{tool}` is a built-in pack; a local pack cannot replace it, use another name such as `{tool}-local`"
                ),
                Origin::Local(_) => format!("tool `{tool}` is already loaded"),
            }));
        }
        if pack_version == 0 {
            return Err(fail("`pack_version` starts at 1".to_owned()));
        }
        if description.trim().is_empty() {
            return Err(fail("`description` is empty".to_owned()));
        }
        let any_program = check_pack_programs(programs).map_err(fail)?;
        let scope = Scope {
            programs,
            any_program,
        };
        check_ids(rules.iter().map(|rule| rule.id.as_str()), "rule").map_err(fail)?;
        for rule in rules {
            check_rule(rule, &scope).map_err(fail)?;
        }
        Ok(any_program)
    }

    fn push_rules(&mut self, tool: &str, rules: &[FlagRule], programs: &[String], any: bool) {
        for rule in rules {
            let mut rule = rule.clone();
            rule.when = scoped(rule.when, programs, any);
            self.rules.push(Compiled {
                tool: tool.to_owned(),
                item: rule,
            });
        }
    }

    fn add_builtin(&mut self, source: &str, text: &str) -> Result<(), PackError> {
        let value = parse(source, text)?;
        let pack: BuiltinPack = serde_json::from_value(value)
            .map_err(|error| PackError::new(source, error.to_string()))?;
        let any = self.check_common(
            source,
            &pack.tool,
            pack.pack_version,
            &pack.description,
            &pack.programs,
            &pack.rules,
        )?;
        let fail = |message: String| PackError::new(source, message);
        let scope = Scope {
            programs: &pack.programs,
            any_program: any,
        };
        for programs in pack.roles.values() {
            check_programs(programs, "roles", &scope).map_err(fail)?;
        }
        if !pack.known_hosts.is_empty() {
            check_list(&pack.known_hosts, "known_hosts", true, false).map_err(fail)?;
        }
        check_ids(pack.exemptions.iter().map(|e| e.id.as_str()), "exemption").map_err(fail)?;
        check_ids(pack.safe.iter().map(|s| s.id.as_str()), "safe rule").map_err(fail)?;
        for exemption in &pack.exemptions {
            exemption
                .when
                .validate(&scope)
                .map_err(|message| fail(format!("exemption `{}`: {message}", exemption.id)))?;
        }
        for safe in &pack.safe {
            if any && safe.when == Matcher::default() {
                return Err(fail(format!(
                    "safe rule `{}` would mark every command as safe",
                    safe.id
                )));
            }
            safe.when
                .validate(&scope)
                .map_err(|message| fail(format!("safe rule `{}`: {message}", safe.id)))?;
        }

        for (role, programs) in &pack.roles {
            self.roles
                .entry(*role)
                .or_default()
                .extend(programs.iter().cloned());
        }
        self.known_hosts.extend(pack.known_hosts.iter().cloned());
        self.push_rules(&pack.tool, &pack.rules, &pack.programs, any);
        for exemption in &pack.exemptions {
            let mut exemption = exemption.clone();
            exemption.when = scoped(exemption.when, &pack.programs, any);
            self.exemptions.push(Compiled {
                tool: pack.tool.clone(),
                item: exemption,
            });
        }
        for safe in &pack.safe {
            let mut safe = safe.clone();
            safe.when = scoped(safe.when, &pack.programs, any);
            self.safe.push(Compiled {
                tool: pack.tool.clone(),
                item: safe,
            });
        }
        self.packs.push(PackInfo {
            tool: pack.tool,
            pack_version: pack.pack_version,
            origin: Origin::BuiltIn,
            rules: pack.rules.len(),
        });
        Ok(())
    }

    /// Add one local pack. The pack can only add flags. A pack that does not validate
    /// changes nothing and gives an error.
    pub fn add_local(&mut self, source: &str, text: &str) -> Result<(), PackError> {
        let value = parse(source, text)?;
        if let Some(field) = BUILTIN_ONLY_FIELDS
            .iter()
            .find(|field| value.get(**field).is_some())
        {
            return Err(PackError::new(
                source,
                format!(
                    "`{field}` is for built-in packs only; a local pack can only add flags, it cannot mark a command as safe or make an exception"
                ),
            ));
        }
        let pack: LocalPack = serde_json::from_value(value)
            .map_err(|error| PackError::new(source, error.to_string()))?;
        let any = self.check_common(
            source,
            &pack.tool,
            pack.pack_version,
            &pack.description,
            &pack.programs,
            &pack.rules,
        )?;
        if pack.rules.is_empty() {
            return Err(PackError::new(
                source,
                "a local pack needs at least one rule",
            ));
        }
        self.push_rules(&pack.tool, &pack.rules, &pack.programs, any);
        self.packs.push(PackInfo {
            tool: pack.tool,
            pack_version: pack.pack_version,
            origin: Origin::Local(source.to_owned()),
            rules: pack.rules.len(),
        });
        Ok(())
    }

    /// Add every `*.json` file in `dir`, in name order. A missing directory adds nothing.
    /// One pack that does not load is an error for the whole directory.
    pub fn with_local_dir(mut self, dir: &Path) -> Result<Self, PackError> {
        let source = dir.display().to_string();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(self),
            Err(error) => return Err(PackError::new(&source, error.to_string())),
        };
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let path = entry
                .map_err(|error| PackError::new(&source, error.to_string()))?
                .path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                files.push(path);
            }
        }
        files.sort();
        for path in files {
            let name = path.display().to_string();
            let size = std::fs::metadata(&path)
                .map_err(|error| PackError::new(&name, error.to_string()))?
                .len();
            if size > MAX_LOCAL_PACK_BYTES {
                return Err(PackError::new(&name, "the file is larger than 1 MiB"));
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|error| PackError::new(&name, error.to_string()))?;
            self.add_local(&name, &text)?;
        }
        Ok(self)
    }

    // ---- Queries for the analysis ----

    pub(crate) fn has_role(&self, program: &str, role: Role) -> bool {
        self.roles
            .get(&role)
            .is_some_and(|programs| programs.contains(program))
    }

    pub(crate) fn known_hosts(&self) -> &[String] {
        &self.known_hosts
    }

    /// Add the flag of each rule that matches. Rules only add flags.
    pub(crate) fn add_flags(&self, cmd: &Command<'_>, flags: &mut Vec<String>) {
        for rule in &self.rules {
            let rule = &rule.item;
            let skipped = rule
                .dry_run
                .is_some_and(|mode| shell_risk::is_dry_run(self, cmd, mode));
            if !skipped && rule.when.matches(cmd) {
                flags.push(rule.flag.clone());
            }
        }
    }

    /// Add the flag of each rule about the package runner (`"package_runner": true`) that
    /// matches. The analysis uses this for a usage request such as `npx tool --help`:
    /// the request does not act, but the runner still downloads and runs the package.
    pub(crate) fn add_package_runner_flags(&self, cmd: &Command<'_>, flags: &mut Vec<String>) {
        for rule in &self.rules {
            let rule = &rule.item;
            if rule.when.package_runner == Some(true) && rule.when.matches(cmd) {
                flags.push(rule.flag.clone());
            }
        }
    }

    /// A built-in pack makes an exception to the general rule `check` for this command.
    pub(crate) fn exempt(&self, check: Check, cmd: &Command<'_>) -> bool {
        self.exemptions
            .iter()
            .any(|exemption| exemption.item.check == check && exemption.item.when.matches(cmd))
    }

    /// A built-in pack marks this command as known safe.
    pub(crate) fn known_safe(&self, cmd: &Command<'_>) -> bool {
        self.safe.iter().any(|safe| safe.item.when.matches(cmd))
    }

    /// Each rule with its name: `tool/rule/id`, `tool/safe/id`, or `tool/exemption/id`.
    fn named_matchers(&self) -> impl Iterator<Item = (String, &Matcher)> {
        let rules = self.rules.iter().map(|rule| {
            let name = format!("{}/rule/{}", rule.tool, rule.item.id);
            (name, &rule.item.when)
        });
        let safe = self.safe.iter().map(|safe| {
            let name = format!("{}/safe/{}", safe.tool, safe.item.id);
            (name, &safe.item.when)
        });
        let exemptions = self.exemptions.iter().map(|exemption| {
            let name = format!("{}/exemption/{}", exemption.tool, exemption.item.id);
            (name, &exemption.item.when)
        });
        rules.chain(safe).chain(exemptions)
    }

    /// Names of all rules: `tool/rule/id`, `tool/safe/id`, and `tool/exemption/id`.
    pub fn rule_ids(&self) -> Vec<String> {
        self.named_matchers().map(|(name, _)| name).collect()
    }

    /// Names of the rules whose matcher matches the command, as in [`Self::rule_ids`].
    #[cfg(test)]
    pub(crate) fn matching_ids(&self, cmd: &Command<'_>) -> Vec<String> {
        self.named_matchers()
            .filter(|(_, when)| when.matches(cmd))
            .map(|(name, _)| name)
            .collect()
    }
}

// ---- The active rule set ----

static ACTIVE: LazyLock<RwLock<Arc<RuleSet>>> =
    LazyLock::new(|| RwLock::new(Arc::new(builtin_or_failed())));

fn builtin_or_failed() -> RuleSet {
    RuleSet::builtin().unwrap_or_else(|error| RuleSet::failed(&error))
}

/// The rule set of [`super::shell_risk::analyze`]. At first it has the built-in packs only.
pub fn active() -> Arc<RuleSet> {
    Arc::clone(&ACTIVE.read().unwrap_or_else(PoisonError::into_inner))
}

/// Replace the active rule set.
pub fn activate(set: RuleSet) {
    *ACTIVE.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(set);
}

/// Load the built-in packs and the local packs in `dir`, and make them active. If a
/// local pack does not load, the active set has the built-in packs and adds
/// [`LOAD_ERROR_FLAG`] to every analysis, so every run waits for the owner.
pub fn activate_local_dir(dir: &Path) -> Result<Vec<PackInfo>, PackError> {
    let builtin = builtin_or_failed();
    match builtin.clone().with_local_dir(dir) {
        Ok(set) => {
            let packs = set.packs().to_vec();
            activate(set);
            Ok(packs)
        }
        Err(error) => {
            activate(builtin.fail_closed(&error));
            Err(error)
        }
    }
}

/// `APASSY_PACKS_DIR`, or `~/Library/Application Support/Apassy/packs`.
pub fn default_local_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(PACKS_DIR_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join("Library")
        .join("Application Support")
        .join("Apassy")
        .join("packs")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin_with(text: &str) -> Result<RuleSet, PackError> {
        let mut set = RuleSet::default();
        set.add_builtin("test.json", text).map(|()| set)
    }

    fn pack(body: &str) -> String {
        format!(
            r#"{{"schema_version": 1, "pack_version": 1, "tool": "t", "description": "Test.",
                "programs": ["tool"], {body}}}"#
        )
    }

    #[test]
    fn builtin_packs_validate() {
        let set = RuleSet::builtin().expect("built-in packs");
        assert_eq!(set.packs().len(), BUILTIN.len());
        assert!(set.load_error().is_none());
        assert!(
            set.packs()
                .iter()
                .all(|pack| pack.origin == Origin::BuiltIn && pack.pack_version >= 1)
        );
        // Roles that the general rules of the analysis need.
        for (program, role) in [
            ("curl", Role::HttpClient),
            ("ssh", Role::Network),
            ("cat", Role::Output),
            ("echo", Role::Output),
            ("base64", Role::Encoder),
            ("python3", Role::HeredocCode),
            ("psql", Role::HeredocSql),
            ("tee", Role::FileWriter),
            ("node", Role::ScriptRunner),
            ("git", Role::Usage),
            ("rm", Role::NoDryRun),
            ("git", Role::NoDryRun),
            ("npm", Role::TaskRunner),
            ("make", Role::TaskRunner),
        ] {
            assert!(set.has_role(program, role), "{program}: {role:?}");
        }
        // BSD `rm -rf / --help` removes `/`. `rm` must never print only usage.
        assert!(!set.has_role("rm", Role::Usage));
        assert!(
            set.known_hosts()
                .iter()
                .any(|host| host == "api.github.com")
        );
    }

    #[test]
    fn schema_mistakes_are_rejected() {
        let rule = |when: &str| {
            pack(&format!(
                r#""rules": [{{"id": "a", "flag": "data_loss", "when": {when}}}]"#
            ))
        };
        let cases = [
            (rule(r#"{"subcommand": ["Push"]}"#), "use lowercase"),
            (rule(r#"{"program": ["other"]}"#), "not in the programs"),
            (rule(r#"{"subcomand": ["push"]}"#), "unknown field `subcomand`"),
            (rule(r#"{"any_of": []}"#), "empty list"),
            (rule(r#"{"not": {}}"#), "without a condition"),
            (
                rule(r#"{"option_value": {"option": ["-x"]}}"#),
                "exactly one",
            ),
            (rule(r#"{"short_option_letter": "rf"}"#), "one lowercase letter"),
            (
                rule(r#"{"operands": {"trim_end": "/"}}"#),
                "needs `count`, `min`, `any`, `all`, or `at`",
            ),
            (
                pack(r#""rules": [{"id": "a", "flag": "allow", "when": {}}]"#),
                "flag `allow`",
            ),
            (
                pack(r#""rules": [{"id": "a", "flag": "data_loss"}, {"id": "a", "flag": "privilege"}]"#),
                "used twice",
            ),
            (
                pack(r#""rules": [{"id": "a", "flag": "data_loss", "dry_run": "always"}]"#),
                "unknown variant `always`",
            ),
            (pack(r#""roles": {"trusted": ["tool"]}"#), "unknown variant `trusted`"),
            (pack(r#""roles": {"output": ["other"]}"#), "not in the programs"),
            (
                r#"{"schema_version": 2, "pack_version": 1, "tool": "t", "description": "Test.", "programs": ["tool"]}"#
                    .to_owned(),
                "schema_version 2 is not supported",
            ),
            (
                r#"{"pack_version": 1, "tool": "t", "description": "Test.", "programs": ["tool"]}"#
                    .to_owned(),
                "`schema_version` is missing",
            ),
            (
                r#"{"schema_version": 1, "pack_version": 0, "tool": "t", "description": "Test.", "programs": ["tool"]}"#
                    .to_owned(),
                "starts at 1",
            ),
            (
                r#"{"schema_version": 1, "pack_version": 1, "tool": "Git", "description": "Test.", "programs": ["tool"]}"#
                    .to_owned(),
                "tool `Git`",
            ),
            (
                r#"{"schema_version": 1, "pack_version": 1, "tool": "t", "description": "Test.", "programs": ["*"], "safe": [{"id": "all"}]}"#
                    .to_owned(),
                "every command as safe",
            ),
            (
                rule(r#"{"operands": {"at": {"index": 0, "in": ["a"], "starts": ["b"]}}}"#),
                "exactly one of `in`, `not_in`, and `starts`",
            ),
            (rule(r#"{"segment_contains": ["Apassy"]}"#), "use lowercase"),
            (rule(r#"{"segment_word_ends": []}"#), "empty list"),
            (rule(r#"{"sql": "any_write"}"#), "unknown variant `any_write`"),
            (
                pack(r#""roles": {"task_runners": ["tool"]}"#),
                "unknown variant `task_runners`",
            ),
        ];
        for (text, expected) in cases {
            let error = builtin_with(&text).expect_err(&text);
            assert!(error.message.contains(expected), "{text}\n{error}");
        }
        builtin_with(&rule(r#"{"subcommand": ["push"]}"#)).expect("valid pack");
    }

    #[test]
    fn a_rule_without_program_uses_the_programs_of_its_pack() {
        let set = builtin_with(&pack(r#""rules": [{"id": "a", "flag": "privilege"}]"#))
            .expect("valid pack");
        let rule = &set.rules[0].item;
        assert_eq!(rule.when.program.as_deref(), Some(&["tool".to_owned()][..]));
    }
}
