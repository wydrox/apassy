//! The kind of action of a command (ADR 0025 §3a).
//!
//! The list is fixed: *read*, *change*, *deploy*, *delete or irreversible*. A production
//! allowance for *read* (ADR 0025 §3b) lets a command run without a question, so a
//! command is a *read* only when that is certain: its program and subcommand are on a
//! fixed list of read-only commands, and it has no output file, no redirect, no inline
//! code, and no setting that can run a program. Everything else is at least a *change*.
//! The `known_safe` answer of the analysis does not make a read: the packs mark local
//! changes (`mkdir`, `npm install`, `git commit`, `op run -- ...`) as known safe.
//!
//! Hard rules on the words of the command, and on the inner commands of `sh -c`,
//! `eval`, `$( )`, and wrappers such as `sudo` and `timeout`, find *deploy* and
//! *delete*. When several rules match, the most dangerous class counts. The analysis
//! can only raise the class. The model never lowers it.

use super::shell_risk::Analysis;

/// What a command does, from the least to the most dangerous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionKind {
    /// Looks at state and changes nothing.
    Read,
    /// Changes state that is easy to repair, or an unclear command.
    Change,
    /// Sends work to a shared or live place: a deploy, a push, a publish.
    Deploy,
    /// Deletes data or cannot be undone.
    Delete,
}

impl ActionKind {
    /// The stable name that is stored and shown.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Change => "change",
            Self::Deploy => "deploy",
            Self::Delete => "delete",
        }
    }

    /// The kind for a stored name. `None` for any other text.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "change" => Some(Self::Change),
            "deploy" => Some(Self::Deploy),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Change => 1,
            Self::Deploy => 2,
            Self::Delete => 3,
        }
    }

    /// The more dangerous of two kinds: Delete, then Deploy, then Change, then Read.
    pub fn more_dangerous(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

use ActionKind::{Change, Delete, Deploy, Read};

/// Inner commands deeper than this (`sh -c "sh -c '...'"`) are a change; their words
/// still count.
const MAX_DEPTH: usize = 4;

/// Words that delete data or cannot be undone. Matched as whole words, in any case.
const DELETE_WORDS: &[&str] = &[
    "delete",
    "del",
    "drop",
    "dropdb",
    "dropuser",
    "truncate",
    "destroy",
    "prune",
    "purge",
    "rm",
    "rmi",
    "rmdir",
    "rmtree",
    "unlink",
    "shred",
    "wipe",
    "erase",
    "mkfs",
    "flush",
    "flushall",
    "flushdb",
    "unpublish",
    "uninstall",
    "remove",
    "terminate",
    "xdelete",
];
/// Word beginnings that delete: `delete-bucket`, `terminate-instances`, `truncate_all`,
/// `--force-with-lease`.
const DELETE_PREFIXES: &[&str] = &[
    "delete-",
    "delete_",
    "destroy-",
    "drop-",
    "drop_",
    "terminate-",
    "purge-",
    "truncate_",
    "force",
];
/// Words that undo database or history state together with a word of [`STATE_WORDS`]:
/// `db:reset`, `pg:reset`, `migrate:fresh`, `db:rollback`, `db:schema:load`.
const RESET_WORDS: &[&str] = &["reset", "rollback", "fresh", "refresh", "load"];
const STATE_WORDS: &[&str] = &["hard", "db", "pg", "migrate", "database", "schema"];
/// Words that send work to a shared or live place.
const DEPLOY_WORDS: &[&str] = &[
    "deploy", "push", "publish", "apply", "release", "rollout", "upload", "promote", "redeploy",
    "rollback",
];
/// Analysis flags that mean a loss of data.
const DELETE_FLAGS: &[&str] = &["data_loss", "irreversible"];
/// Analysis flags that say nothing about the kind of action. Every other flag (such
/// as `system_change` or `remote_code`) makes at least a change.
const NEUTRAL_FLAGS: &[&str] = &[
    "secret_output",
    "production",
    "injection_phrase",
    "foreign_host",
];
/// SQL function names with these parts delete: `pg_terminate_backend`, `lo_unlink`,
/// `pg_drop_replication_slot`, and in inline code `os.remove`, `shutil.rmtree`.
const DELETE_CALL_PARTS: &[&str] = &[
    "drop",
    "delete",
    "truncate",
    "unlink",
    "terminate",
    "destroy",
    "purge",
    "wipe",
    "rmtree",
    "remove",
];

/// The kind of action of `command` (its words, with the program first), by the hard
/// rules and by the flags of its analysis.
///
/// - *Read*: a read-only program or subcommand of a fixed list (`ls`, `cat`,
///   `kubectl get`, `git log`, `gh pr view`, `aws ec2 describe-*`, `stripe ... list`,
///   a plain `SELECT` in `psql -c`, ...), with no output file, redirect, pipe, inline
///   code, or setting that runs a program, and no analysis flag or known write.
/// - *Delete*: a delete word anywhere (`rm`, `DROP`, `DELETE`, `truncate`, `destroy`,
///   `--force`, `delete-*`, ...), `reset --hard`, `db:reset`, `git push` with `-f`,
///   `--delete`, `:branch` or `+branch`, a deleting SQL function, or an analysis flag
///   for data loss.
/// - *Deploy*: `deploy`, `push`, `publish`, `apply`, `release`, `rollout`, bare
///   `vercel` or `vercel --prod`, `helm install|upgrade`, `pulumi up`.
/// - *Change*: everything else, also inline code (`python -c`, `sh -c`), `git -c`,
///   output files, and SQL other than a plain `SELECT`.
pub fn classify(command: &[String], analysis: &Analysis) -> ActionKind {
    let mut kind = classify_argv(command, 0);
    // The words of a certain read are data (`kubectl get deploy`, `grep drop`).
    if kind != Read {
        kind = kind.more_dangerous(danger_in_words(command));
    }
    for flag in &analysis.flags {
        let floor = if DELETE_FLAGS.contains(&flag.as_str()) {
            Delete
        } else if NEUTRAL_FLAGS.contains(&flag.as_str()) {
            Read
        } else {
            Change
        };
        kind = kind.more_dangerous(floor);
    }
    if analysis.known_write {
        kind = kind.more_dangerous(Change);
    }
    kind
}

/// Deploy or Delete when a hard word rule matches anywhere in the command, also inside
/// quoted inner commands and inline code. `Read` when no word rule matches.
fn danger_in_words(command: &[String]) -> ActionKind {
    let words = words_of(command);
    let has = |list: &[&str]| words.iter().any(|w| list.contains(&w.as_str()));
    if has(DELETE_WORDS)
        || words
            .iter()
            .any(|w| DELETE_PREFIXES.iter().any(|p| w.starts_with(p)))
        || (has(RESET_WORDS) && has(STATE_WORDS))
        || command.iter().any(|arg| deleting_call(arg))
    {
        Delete
    } else if has(DEPLOY_WORDS) {
        Deploy
    } else {
        Read
    }
}

/// The lowercase words of a command: each argument split at spaces, quotes, shell
/// marks, `=`, `:`, and similar, with a path cut to its last part and leading dashes
/// removed. `--rm` (remove the container after the run) is left out.
fn words_of(command: &[String]) -> Vec<String> {
    let mut words = Vec::new();
    for arg in command {
        let lower = arg.to_lowercase();
        for piece in lower.split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '"' | '\''
                        | ';'
                        | '|'
                        | '&'
                        | '('
                        | ')'
                        | '<'
                        | '>'
                        | '='
                        | ','
                        | ':'
                        | '`'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | '$'
                        | '\\'
                        | '!'
                )
        }) {
            if piece == "--rm" {
                continue;
            }
            let name = piece.rsplit('/').next().unwrap_or(piece);
            let name = name.trim_start_matches('-');
            if !name.is_empty() {
                words.push(name.to_owned());
            }
        }
    }
    words
}

/// A call `name(` whose name deletes (SQL `pg_terminate_backend(1)`, `lo_unlink(1)`,
/// Python `os.remove(p)`).
fn deleting_call(text: &str) -> bool {
    function_calls(text).iter().any(|name| {
        DELETE_CALL_PARTS
            .iter()
            .any(|part| name.split('_').any(|piece| piece == *part) || name == part)
    })
}

/// The names before `(` in `text`, in lowercase (`count`, `pg_sleep`, `in`).
fn function_calls(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let bytes = lower.as_bytes();
    let mut names = Vec::new();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != b'(' {
            continue;
        }
        let mut end = i;
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            start -= 1;
        }
        if start < end {
            names.push(lower[start..end].to_owned());
        }
    }
    names
}

/// The kind of one simple command (program and arguments) by its program rules. The
/// word rules of [`danger_in_words`] are separate.
fn classify_argv(argv: &[String], depth: usize) -> ActionKind {
    if depth > MAX_DEPTH {
        return Change;
    }
    let mut floor = Read;
    let mut i = 0;
    // Assignments and wrappers before the program.
    loop {
        let Some(first) = argv.get(i) else {
            return floor.more_dangerous(Change);
        };
        if is_assignment(first) {
            if !harmless_assignment(first) {
                floor = Change;
            }
            i += 1;
            continue;
        }
        let name = program_name(first);
        let rest = &argv[i + 1..];
        let skip = match name.as_str() {
            "sudo" | "doas" => {
                floor = Change;
                options_end(
                    rest,
                    &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
                )
            }
            "env" => {
                // `env -S TEXT` splits a text into words: unclear.
                if rest
                    .iter()
                    .any(|a| a == "-S" || a.starts_with("--split-string"))
                {
                    floor = Change;
                }
                options_end(rest, &["-u", "--unset", "-C", "--chdir", "-S"])
            }
            "timeout" => options_end(rest, &["-s", "--signal", "-k", "--kill-after"]) + 1,
            "nice" => options_end(rest, &["-n", "--adjustment"]),
            "nohup" | "time" | "command" | "exec" | "stdbuf" | "caffeinate" => {
                options_end(rest, &[])
            }
            "xargs" | "watch" | "parallel" => {
                floor = Change;
                options_end(
                    rest,
                    &["-I", "-n", "-P", "-L", "-d", "-E", "-s", "--interval"],
                )
            }
            _ => break,
        };
        i += 1 + skip;
    }
    let program = &argv[i];
    let args = &argv[i + 1..];
    let mut kind = classify_program(&program_name(program), args, depth);
    // A path names a program the agent may have written (`./ls`).
    if kind == Read && program.contains('/') {
        kind = Change;
    }
    floor.more_dangerous(kind)
}

/// The index of the first argument after the options of a wrapper. `with_value` are
/// options that take the next argument.
fn options_end(args: &[String], with_value: &[&str]) -> usize {
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        if arg == "--" {
            return i + 1;
        }
        if !arg.starts_with('-') || arg == "-" {
            return i;
        }
        i += if with_value.contains(&arg.as_str()) {
            2
        } else {
            1
        };
    }
    i
}

/// `NAME=value` with a shell name.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// An assignment that cannot make a read program run other code. Pagers, editors,
/// config files, `PATH`, `LD_*`, `GIT_*`, and all other names can.
fn harmless_assignment(word: &str) -> bool {
    let name = word.split('=').next().unwrap_or_default();
    const NAMES: &[&str] = &[
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "PGHOST",
        "PGPORT",
        "PGUSER",
        "PGDATABASE",
        "PGSSLMODE",
        "NO_COLOR",
        "TERM",
        "LANG",
        "LC_ALL",
        "TZ",
        "GH_REPO",
        "GH_HOST",
    ];
    const SUFFIXES: &[&str] = &["_TOKEN", "_API_KEY", "_SECRET", "_PASSWORD"];
    NAMES.contains(&name) || SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// The lowercase last path part of a program.
fn program_name(program: &str) -> String {
    program.rsplit('/').next().unwrap_or(program).to_lowercase()
}

/// Programs that only read, with any arguments that pass [`plain_args`].
const READ_PROGRAMS: &[&str] = &[
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "du",
    "df",
    "file",
    "stat",
    "tree",
    "cut",
    "nl",
    "tr",
    "column",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "pwd",
    "whoami",
    "id",
    "uname",
    "uptime",
    "nproc",
    "sw_vers",
    "printenv",
    "echo",
    "printf",
    "which",
    "true",
    "ps",
    "pgrep",
    "lsof",
    "free",
    "vm_stat",
    "dig",
    "nslookup",
    "host",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "diff",
    "cmp",
    "sha256sum",
    "sha1sum",
    "shasum",
    "md5sum",
    "md5",
    "jq",
    "sort",
];
/// Programs that answer `--version` or `--help` without other work.
const VERSION_PROGRAMS: &[&str] = &[
    "git",
    "gh",
    "glab",
    "kubectl",
    "helm",
    "aws",
    "gcloud",
    "az",
    "doctl",
    "stripe",
    "fly",
    "flyctl",
    "heroku",
    "terraform",
    "tofu",
    "pulumi",
    "docker",
    "podman",
    "vercel",
    "wrangler",
    "netlify",
    "firebase",
    "supabase",
    "railway",
    "sentry-cli",
    "psql",
    "mysql",
    "sqlite3",
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "node",
    "deno",
    "python",
    "python3",
    "ruby",
    "cargo",
    "rustc",
    "go",
    "java",
];
const VERSION_ARGS: &[&str] = &["--version", "-v", "-V", "version", "--help", "-h", "help"];
/// Shells: `-c TEXT` runs the text.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];
/// Programs whose `-o` or `--output` is an output format, not a file.
const FORMAT_PROGRAMS: &[&str] = &["kubectl", "helm", "aws", "doctl"];
const FORMATS: &[&str] = &[
    "json",
    "yaml",
    "yml",
    "wide",
    "name",
    "text",
    "table",
    "tsv",
    "yaml-stream",
];
const FORMAT_PREFIXES: &[&str] = &["jsonpath", "go-template", "custom-columns", "template"];

/// The kind of a program with its arguments.
fn classify_program(name: &str, args: &[String], depth: usize) -> ActionKind {
    if args.len() == 1
        && VERSION_ARGS.contains(&args[0].as_str())
        && VERSION_PROGRAMS.contains(&name)
    {
        return Read;
    }
    if SHELLS.contains(&name) {
        return match shell_script(args) {
            Some(script) => Change.more_dangerous(classify_script(script, depth)),
            None => Change,
        };
    }
    if name == "eval" {
        return Change.more_dangerous(classify_script(&args.join(" "), depth));
    }
    if DELETE_WORDS.contains(&name) || name == "dd" || name.starts_with("mkfs") {
        return Delete;
    }
    let read = match name {
        _ if READ_PROGRAMS.contains(&name) => read_tool(name, args),
        "find" => !args.iter().any(|a| {
            matches!(
                a.as_str(),
                "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir" | "-fls"
            ) || a.starts_with("-fprint")
        }),
        "git" => return git(args),
        "gh" | "glab" => gh(name, args),
        "kubectl" => kubectl(args),
        "helm" => return helm(args),
        "aws" => return aws(args),
        "stripe" => stripe(args),
        "fly" | "flyctl" => fly(args),
        "terraform" | "tofu" => terraform(args),
        "docker" | "podman" => docker(args),
        "vercel" => return vercel(args),
        "wrangler" => wrangler(args),
        "heroku" => heroku(args),
        "pulumi" => {
            return if args.iter().any(|a| a == "up" || a == "update") {
                Deploy
            } else {
                Change
            };
        }
        "psql" => return sql_client(args, &PSQL),
        "mysql" | "mariadb" => return sql_client(args, &MYSQL),
        "sqlite3" => return sqlite(args),
        _ => false,
    };
    if read && plain_args(name, args) {
        Read
    } else {
        Change
    }
}

/// No shell mark (a redirect, a pipe, a command list, a substitution) and no option
/// that writes an output file.
fn plain_args(name: &str, args: &[String]) -> bool {
    !args.iter().any(|a| has_shell_mark(a)) && !writes_output(name, args)
}

fn has_shell_mark(arg: &str) -> bool {
    arg.contains(['>', '<', '|', ';', '`', '&']) || arg.contains("$(")
}

/// An option that writes a file: `-o`, `--output`, `--out`, `--outfile`, `-out`,
/// `--log-file`, `--tee`. For [`FORMAT_PROGRAMS`], `-o json` is a format.
fn writes_output(name: &str, args: &[String]) -> bool {
    const SPLIT: &[&str] = &[
        "-o",
        "--output",
        "--out",
        "--outfile",
        "--out-file",
        "--output-file",
        "--output-dir",
        "--output-directory",
        "-out",
        "--log-file",
        "--tee",
    ];
    let format = |value: Option<&str>| {
        FORMAT_PROGRAMS.contains(&name)
            && value.is_some_and(|v| {
                let v = v.to_lowercase();
                FORMATS.contains(&v.as_str()) || FORMAT_PREFIXES.iter().any(|p| v.starts_with(p))
            })
    };
    // For these programs `-o` is an option without a file: only matching, long list
    // without groups, or an output format.
    let short_o_is_file = !["grep", "egrep", "fgrep", "rg", "ag", "ls", "ps"].contains(&name);
    args.iter().enumerate().any(|(i, arg)| {
        let lower = arg.to_lowercase();
        if !short_o_is_file && lower.starts_with("-o") && !lower.starts_with("--") {
            return false;
        }
        if SPLIT.contains(&lower.as_str()) {
            return !format(args.get(i + 1).map(String::as_str));
        }
        if let Some((option, value)) = lower.split_once('=')
            && SPLIT.contains(&option)
        {
            return !format(Some(value));
        }
        // `-ojson` and `-ofile`.
        if let Some(value) = lower.strip_prefix("-o")
            && !lower.starts_with("--")
            && !value.is_empty()
        {
            return !format(Some(value));
        }
        false
    })
}

/// The arguments that are not options. `with_value` are options that take the next
/// argument. An option with `=` keeps its value.
fn operands<'a>(args: &'a [String], with_value: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        if arg == "--" {
            out.extend(args[i + 1..].iter().map(String::as_str));
            break;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            i += if with_value.contains(&arg.as_str()) {
                2
            } else {
                1
            };
            continue;
        }
        out.push(arg.as_str());
        i += 1;
    }
    out
}

fn read_tool(name: &str, args: &[String]) -> bool {
    match name {
        // `rg --pre COMMAND` runs a program for each file.
        "rg" => !args.iter().any(|a| a.starts_with("--pre")),
        // `date -s` sets the clock.
        "date" => !args.iter().any(|a| a == "-s" || a.starts_with("--set")),
        _ => true,
    }
}

/// The text after `-c` of a shell (`bash -eo pipefail -c TEXT`). `None` for a script
/// file or standard input.
fn shell_script(args: &[String]) -> Option<&str> {
    let mut inline = false;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        i += 1;
        if arg == "--" {
            break;
        }
        if arg.starts_with("--") {
            continue;
        }
        if (arg.starts_with('-') || arg.starts_with('+')) && arg.len() > 1 {
            for c in arg.chars().skip(1) {
                match c {
                    'c' => inline = true,
                    // `-o pipefail`, `-O extglob`: the next argument is a name.
                    'o' | 'O' => i += 1,
                    _ => {}
                }
            }
            continue;
        }
        return inline.then_some(arg.as_str());
    }
    None
}

/// The most dangerous kind of the commands of a shell text.
fn classify_script(script: &str, depth: usize) -> ActionKind {
    script_commands(script)
        .iter()
        .map(|words| classify_argv(words, depth + 1))
        .fold(Read, ActionKind::more_dangerous)
}

/// The simple commands of a shell text: words split at `;`, `&`, `|`, new lines, `(`,
/// `)`, `{`, `}`, backquotes, and `$(`, with quotes removed. A redirect and its target
/// are left out, and the lines of a here-document become commands. Enough to find
/// inner commands: the whole text is at least a change.
fn script_commands(script: &str) -> Vec<Vec<String>> {
    struct Builder {
        commands: Vec<Vec<String>>,
        words: Vec<String>,
        word: String,
        in_word: bool,
        skip_word: bool,
    }
    impl Builder {
        fn end_word(&mut self) {
            if self.in_word {
                let word = std::mem::take(&mut self.word);
                if self.skip_word {
                    self.skip_word = false;
                } else {
                    self.words.push(word);
                }
                self.in_word = false;
            }
        }
        fn end_command(&mut self) {
            self.end_word();
            self.skip_word = false;
            if !self.words.is_empty() {
                self.commands.push(std::mem::take(&mut self.words));
            }
        }
    }
    let mut b = Builder {
        commands: Vec::new(),
        words: Vec::new(),
        word: String::new(),
        in_word: false,
        skip_word: false,
    };
    let mut chars = script.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                b.in_word = true;
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    b.word.push(d);
                }
            }
            '"' => {
                b.in_word = true;
                while let Some(d) = chars.next() {
                    match d {
                        '"' => break,
                        '\\' => {
                            if let Some(e) = chars.next() {
                                b.word.push(e);
                            }
                        }
                        _ => b.word.push(d),
                    }
                }
            }
            '\\' => {
                b.in_word = true;
                if let Some(d) = chars.next()
                    && d != '\n'
                {
                    b.word.push(d);
                }
            }
            '#' if !b.in_word => {
                while chars.peek().is_some_and(|d| *d != '\n') {
                    chars.next();
                }
            }
            '$' if chars.peek() == Some(&'{') => {
                b.in_word = true;
                b.word.push('$');
                for d in chars.by_ref() {
                    b.word.push(d);
                    if d == '}' {
                        break;
                    }
                }
            }
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                b.end_command();
            }
            '>' | '<' => {
                // `2>` and `2<`: the number is the file descriptor, not a word.
                if b.in_word && !b.word.is_empty() && b.word.chars().all(|d| d.is_ascii_digit()) {
                    b.word.clear();
                    b.in_word = false;
                }
                b.end_word();
                while matches!(chars.peek(), Some('>' | '<' | '&' | '|')) {
                    chars.next();
                }
                // `<(command)` is a process substitution: its command counts.
                b.skip_word = chars.peek() != Some(&'(');
            }
            ';' | '&' | '|' | '\n' | '(' | ')' | '`' | '{' | '}' => b.end_command(),
            c if c.is_whitespace() => b.end_word(),
            c => {
                b.in_word = true;
                b.word.push(c);
            }
        }
    }
    b.end_command();
    b.commands
}

/// `git`: a fixed list of read subcommands; `push` is a deploy or a delete.
fn git(args: &[String]) -> ActionKind {
    // Global options before the subcommand.
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        match arg.as_str() {
            // `-c` and `--config-env` set any setting, also a program to run.
            "-c" | "--config-env" => return Change,
            "-C" => i += 2,
            "--no-pager"
            | "-P"
            | "--no-optional-locks"
            | "--bare"
            | "--literal-pathspecs"
            | "--no-replace-objects" => i += 1,
            a if a.starts_with("--git-dir=")
                || a.starts_with("--work-tree=")
                || a.starts_with("--namespace=") =>
            {
                i += 1
            }
            a if a.starts_with('-') => return Change,
            _ => break,
        }
    }
    let Some(sub) = args.get(i) else {
        return Change;
    };
    let rest = &args[i + 1..];
    let has = |words: &[&str]| rest.iter().any(|a| words.contains(&a.as_str()));
    let first = rest.first().map(String::as_str);
    match sub.as_str() {
        "push" => return push(rest),
        "clean" | "filter-branch" | "filter-repo" => return Delete,
        "branch" | "tag" if has(&["-d", "-D", "--delete"]) => return Delete,
        "stash" if matches!(first, Some("drop" | "clear")) => return Delete,
        "reflog" if matches!(first, Some("expire" | "delete")) => return Delete,
        "update-ref" if has(&["-d"]) => return Delete,
        _ => {}
    }
    let read = match sub.as_str() {
        "log" | "show" | "status" | "diff" | "blame" | "shortlog" | "describe" | "rev-parse"
        | "ls-files" | "ls-tree" | "ls-remote" | "cat-file" | "rev-list" | "grep" | "version"
        | "help" | "whatchanged" | "show-ref" | "merge-base" => !rest.iter().any(|a| {
            a == "--ext-diff"
                || a.starts_with("--open-files-in-pager")
                || (sub == "grep" && a.starts_with("-O"))
        }),
        "branch" => rest.iter().all(|a| {
            matches!(
                a.as_str(),
                "-a" | "-r"
                    | "-v"
                    | "-vv"
                    | "--all"
                    | "--remotes"
                    | "--verbose"
                    | "--list"
                    | "-l"
                    | "--show-current"
            )
        }),
        "remote" => matches!(first, None | Some("-v" | "show" | "get-url")),
        "tag" => matches!(first, None | Some("-l" | "--list")),
        "stash" => matches!(first, Some("list" | "show")),
        "worktree" => first == Some("list"),
        "reflog" => matches!(first, None | Some("show")),
        "config" => {
            has(&["--get", "--get-all", "--get-regexp", "--list", "-l"])
                && !rest.iter().any(|a| {
                    matches!(
                        a.as_str(),
                        "--add"
                            | "--unset"
                            | "--unset-all"
                            | "--replace-all"
                            | "--rename-section"
                            | "--remove-section"
                            | "-e"
                            | "--edit"
                    )
                })
        }
        _ => false,
    };
    if read && plain_args("git", rest) {
        Read
    } else {
        Change
    }
}

/// `git push`: a deploy; a delete with a force or delete option, `--mirror`, or a
/// refspec that deletes (`:branch`) or forces (`+branch`).
fn push(args: &[String]) -> ActionKind {
    let deletes = args.iter().any(|a| {
        let short_cluster = a.starts_with('-') && !a.starts_with("--");
        (short_cluster && a.contains(['f', 'd']))
            || a.starts_with("--force")
            || a == "--delete"
            || a == "--mirror"
            || a == "--prune"
            || a.starts_with(':')
            || a.starts_with('+')
    });
    if deletes { Delete } else { Deploy }
}

/// `gh` and `glab`: `NOUN view|list|status|...`, `search`, `auth status`, and a
/// `gh api` GET without fields.
fn gh(name: &str, args: &[String]) -> bool {
    const NOUNS: &[&str] = &[
        "pr",
        "mr",
        "issue",
        "run",
        "workflow",
        "release",
        "repo",
        "gist",
        "label",
        "secret",
        "variable",
        "cache",
        "ruleset",
        "project",
        "org",
        "codespace",
        "ssh-key",
        "gpg-key",
        "alias",
        "ci",
        "pipeline",
        "job",
    ];
    const VERBS: &[&str] = &["view", "list", "ls", "status", "checks", "diff"];
    let first = args.first().map(String::as_str);
    let second = args.get(1).map(String::as_str);
    match first {
        Some("status") => true,
        Some("search") => true,
        Some("auth") => second == Some("status"),
        Some("api") if name == "gh" => {
            let mut get = true;
            for (i, a) in args.iter().enumerate() {
                let method = if a == "-X" || a == "--method" {
                    args.get(i + 1).map(String::as_str)
                } else if let Some(m) = a.strip_prefix("--method=") {
                    Some(m)
                } else if let Some(m) = a.strip_prefix("-X") {
                    (!m.is_empty()).then_some(m)
                } else {
                    None
                };
                if method.is_some_and(|m| !m.eq_ignore_ascii_case("get")) {
                    get = false;
                }
                // Fields and an input body make a POST.
                if matches!(
                    a.as_str(),
                    "-f" | "-F" | "--field" | "--raw-field" | "--input"
                ) || a.starts_with("--field=")
                    || a.starts_with("--raw-field=")
                    || a.starts_with("--input=")
                {
                    get = false;
                }
            }
            get
        }
        Some(noun) if NOUNS.contains(&noun) => second.is_some_and(|v| VERBS.contains(&v)),
        _ => false,
    }
}

/// `kubectl`: get, describe, logs, and other reads; not with a kubeconfig file of the
/// command (its exec plugin is a program).
fn kubectl(args: &[String]) -> bool {
    if args.iter().any(|a| a.starts_with("--kubeconfig")) {
        return false;
    }
    let ops = operands(
        args,
        &[
            "-n",
            "--namespace",
            "--context",
            "--cluster",
            "--user",
            "-s",
            "--server",
            "-l",
            "--selector",
            "-o",
            "--output",
            "-c",
            "--container",
            "--field-selector",
            "--sort-by",
            "--since",
            "--tail",
            "--request-timeout",
            "-L",
            "--label-columns",
            "--as",
            "--as-group",
        ],
    );
    match ops.first().copied() {
        Some(
            "get" | "describe" | "logs" | "top" | "explain" | "api-resources" | "api-versions"
            | "version" | "events",
        ) => true,
        Some("cluster-info") => !ops.contains(&"dump"),
        Some("config") => matches!(
            ops.get(1).copied(),
            Some("view" | "get-contexts" | "current-context" | "get-clusters" | "get-users")
        ),
        Some("auth") => matches!(ops.get(1).copied(), Some("can-i" | "whoami")),
        _ => false,
    }
}

/// `helm`: reads; `install` and `upgrade` are a deploy.
fn helm(args: &[String]) -> ActionKind {
    if args.iter().any(|a| a.starts_with("--kubeconfig")) {
        return Change;
    }
    let ops = operands(
        args,
        &["-n", "--namespace", "--kube-context", "-o", "--output"],
    );
    match ops.first().copied() {
        Some("install" | "upgrade") => Deploy,
        Some(
            "list" | "ls" | "status" | "history" | "show" | "search" | "version" | "get" | "env",
        ) if plain_args("helm", args) => Read,
        _ => Change,
    }
}

/// `aws SERVICE OPERATION`: `describe-*`, `list-*`, `get-*`, `head-*`, `s3 ls`, and a
/// few others; `s3 rb` is a delete.
fn aws(args: &[String]) -> ActionKind {
    let ops = operands(
        args,
        &[
            "--profile",
            "--region",
            "--output",
            "--endpoint-url",
            "--query",
            "--color",
            "--cli-read-timeout",
            "--cli-connect-timeout",
            "--ca-bundle",
        ],
    );
    let (Some(service), Some(op)) = (ops.first().copied(), ops.get(1).copied()) else {
        return Change;
    };
    if service == "s3" && op == "rb" {
        return Delete;
    }
    let read = match (service, op) {
        // Both write the object to a local file.
        ("s3api", "get-object" | "get-object-torrent") => false,
        ("s3", "ls") | ("logs", "tail" | "filter-log-events") => true,
        ("dynamodb", "scan" | "query") => true,
        ("configure", "list" | "get" | "list-profiles") => true,
        (_, op) => ["describe-", "list-", "get-", "head-"]
            .iter()
            .any(|p| op.starts_with(p)),
    };
    if read && plain_args("aws", args) {
        Read
    } else {
        Change
    }
}

/// `stripe RESOURCE list|retrieve`, `stripe get PATH`, `stripe logs tail`, status.
fn stripe(args: &[String]) -> bool {
    let ops = operands(
        args,
        &[
            "--api-key",
            "--project-name",
            "-p",
            "--stripe-account",
            "--stripe-version",
            "-d",
            "--data",
            "-e",
            "--expand",
            "--limit",
            "--starting-after",
            "--ending-before",
            "--color",
            "--log-level",
            "--device-name",
        ],
    );
    match ops.first().copied() {
        Some("get" | "status" | "version") => true,
        Some("logs") => ops.get(1).copied() == Some("tail"),
        Some(_) => matches!(ops.get(1).copied(), Some("list" | "retrieve")),
        None => false,
    }
}

/// `fly status`, `fly logs`, `fly NOUN list|show|status`.
fn fly(args: &[String]) -> bool {
    let ops = operands(
        args,
        &[
            "-a",
            "--app",
            "-c",
            "--config",
            "-r",
            "--region",
            "-t",
            "--access-token",
            "--org",
        ],
    );
    match ops.first().copied() {
        Some("status" | "logs" | "releases" | "version" | "info" | "history") => true,
        Some("ssh" | "proxy" | "sftp" | "console" | "deploy") | None => false,
        Some(_) => matches!(ops.get(1).copied(), Some("list" | "ls" | "show" | "status")),
    }
}

/// `terraform show|output|version|providers|graph`, `state list|show`, `workspace
/// list|show`. `plan` runs providers and data sources of the project.
fn terraform(args: &[String]) -> bool {
    let ops = operands(args, &[]);
    match ops.first().copied() {
        Some("show" | "output" | "version" | "providers" | "graph") => true,
        Some("state" | "workspace") => matches!(ops.get(1).copied(), Some("list" | "show")),
        _ => false,
    }
}

/// `docker ps|images|logs|inspect|...`, `docker NOUN ls|inspect`, `docker compose
/// ps|logs|config|...`. Not with a config folder of the command (credential helpers).
fn docker(args: &[String]) -> bool {
    if args
        .iter()
        .any(|a| a == "--config" || a.starts_with("--config="))
    {
        return false;
    }
    let ops = operands(
        args,
        &[
            "-H",
            "--host",
            "--context",
            "-c",
            "-l",
            "--log-level",
            "-f",
            "--file",
            "-p",
            "--project-name",
            "--profile",
            "--env-file",
            "--project-directory",
            "--format",
            "--filter",
            "--since",
            "--until",
            "--tail",
            "-n",
        ],
    );
    let second = ops.get(1).copied();
    match ops.first().copied() {
        Some(
            "ps" | "images" | "version" | "info" | "inspect" | "logs" | "top" | "stats" | "history"
            | "port",
        ) => true,
        Some("image") => matches!(second, Some("ls" | "list" | "inspect" | "history")),
        Some("container") => matches!(
            second,
            Some("ls" | "list" | "inspect" | "logs" | "top" | "port" | "diff" | "stats")
        ),
        Some(
            "volume" | "network" | "context" | "node" | "service" | "stack" | "secret" | "config",
        ) => matches!(second, Some("ls" | "list" | "inspect")),
        Some("system") => matches!(second, Some("df" | "info" | "events")),
        Some("compose") => matches!(
            second,
            Some("ps" | "logs" | "config" | "ls" | "images" | "top" | "version")
        ),
        _ => false,
    }
}

/// `vercel` with no subcommand, `vercel deploy`, `vercel PATH`, and `vercel --prod`
/// deploy; `ls`, `inspect`, `logs`, `whoami`, `NOUN ls` read.
fn vercel(args: &[String]) -> ActionKind {
    let ops = operands(
        args,
        &[
            "--token",
            "-t",
            "--scope",
            "-S",
            "--cwd",
            "-A",
            "--local-config",
            "-Q",
            "--global-config",
        ],
    );
    let read = match ops.first().copied() {
        None | Some("deploy") => return Deploy,
        Some(path) if path.contains(['/', '.']) => return Deploy,
        Some("ls" | "list" | "inspect" | "logs" | "whoami") => true,
        Some(
            "env" | "domains" | "dns" | "certs" | "alias" | "aliases" | "projects" | "project"
            | "teams",
        ) => matches!(ops.get(1).copied(), Some("ls" | "list")),
        Some(_) => false,
    };
    if args.iter().any(|a| a == "--prod") && !read {
        return Deploy;
    }
    if read && plain_args("vercel", args) {
        Read
    } else {
        Change
    }
}

/// `wrangler whoami|tail`, `wrangler GROUP list|info|...`, `wrangler kv key list`.
fn wrangler(args: &[String]) -> bool {
    const GROUPS: &[&str] = &[
        "kv",
        "d1",
        "r2",
        "deployments",
        "versions",
        "secret",
        "queues",
        "pages",
        "vectorize",
        "hyperdrive",
        "workflows",
    ];
    const NOUNS: &[&str] = &[
        "key",
        "namespace",
        "bucket",
        "deployment",
        "project",
        "index",
    ];
    const VERBS: &[&str] = &["list", "get", "info", "view", "status"];
    let ops = operands(
        args,
        &[
            "-c",
            "--config",
            "-e",
            "--env",
            "--binding",
            "--namespace-id",
        ],
    );
    let at = |i: usize| ops.get(i).copied();
    match at(0) {
        Some("whoami" | "tail") => true,
        Some(group) if GROUPS.contains(&group) => {
            at(1).is_some_and(|v| VERBS.contains(&v))
                || (at(1).is_some_and(|n| NOUNS.contains(&n))
                    && at(2).is_some_and(|v| VERBS.contains(&v)))
        }
        _ => false,
    }
}

/// `heroku apps|ps|logs|config|releases|...` and their `:info`, `:get` forms.
fn heroku(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some(
            "apps"
                | "apps:info"
                | "ps"
                | "logs"
                | "config"
                | "config:get"
                | "releases"
                | "releases:info"
                | "addons"
                | "addons:info"
                | "domains"
                | "status"
                | "whoami"
                | "auth:whoami"
                | "pg"
                | "pg:info"
                | "info"
                | "access"
                | "drains"
                | "features"
                | "regions"
                | "stack"
                | "buildpacks"
                | "webhooks"
        )
    )
}

/// The options of an SQL client.
struct SqlClient {
    /// Options with the query as the next argument or after `=`.
    query: &'static [&'static str],
    /// Options with a value that reads nothing and writes nothing.
    with_value: &'static [&'static str],
    /// Options without a value that are safe.
    flags: &'static [&'static str],
    /// Operands (database, user) at most.
    max_operands: usize,
    /// Meta commands that only read (`\d`, `\l`).
    meta: bool,
}

const PSQL: SqlClient = SqlClient {
    query: &["-c", "--command"],
    with_value: &[
        "-h",
        "--host",
        "-p",
        "--port",
        "-U",
        "--username",
        "-d",
        "--dbname",
        "-P",
        "--pset",
        "-F",
        "--field-separator",
        "-R",
        "--record-separator",
        "-v",
        "--set",
        "--variable",
    ],
    flags: &[
        "-t",
        "--tuples-only",
        "-A",
        "--no-align",
        "-X",
        "--no-psqlrc",
        "-q",
        "--quiet",
        "-x",
        "--expanded",
        "-w",
        "--no-password",
        "-W",
        "--password",
        "-a",
        "-e",
        "-E",
        "-b",
        "-n",
        "--csv",
        "-H",
        "--html",
        "-l",
        "--list",
        "-1",
        "--single-transaction",
    ],
    max_operands: 2,
    meta: true,
};

const MYSQL: SqlClient = SqlClient {
    query: &["-e", "--execute"],
    with_value: &[
        "-h",
        "--host",
        "-P",
        "--port",
        "-u",
        "--user",
        "-D",
        "--database",
        "--protocol",
    ],
    flags: &[
        "-N",
        "--skip-column-names",
        "-B",
        "--batch",
        "-s",
        "--silent",
        "-t",
        "--table",
        "-E",
        "--vertical",
        "-r",
        "--raw",
        "-p",
        "--password",
        "--ssl",
        "--ssl-mode",
    ],
    max_operands: 1,
    meta: false,
};

/// An SQL client with only plain `SELECT` queries in its query options is a read. A
/// delete word in the query is found by the word rules.
fn sql_client(args: &[String], client: &SqlClient) -> ActionKind {
    let mut queries = Vec::new();
    let mut operands = 0;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        i += 1;
        let (option, attached) = match arg.split_once('=') {
            Some((o, v)) if o.starts_with("--") => (o, Some(v)),
            _ => (arg.as_str(), None),
        };
        if client.query.contains(&option) {
            match attached.or_else(|| args.get(i).map(String::as_str)) {
                Some(query) => queries.push(query),
                None => return Change,
            }
            if attached.is_none() {
                i += 1;
            }
        } else if client.with_value.contains(&option) {
            if attached.is_none() {
                i += 1;
            }
        } else if !option.starts_with('-') {
            operands += 1;
        } else if !(client.flags.contains(&option)
            // `mysql -pSECRET`: the password is attached.
            || (!client.meta && option.starts_with("-p") && !option.starts_with("--")))
        {
            return Change;
        }
        if has_shell_mark(arg) && !queries.contains(&arg.as_str()) {
            return Change;
        }
    }
    let read = !queries.is_empty()
        && operands <= client.max_operands
        && queries
            .iter()
            .all(|q| plain_select(q) || (client.meta && psql_meta_read(q)));
    if read { Read } else { Change }
}

/// `sqlite3 [OPTIONS] DATABASE SQL...` with plain `SELECT` statements only.
fn sqlite(args: &[String]) -> ActionKind {
    const FLAGS: &[&str] = &[
        "-readonly",
        "-json",
        "-csv",
        "-header",
        "-noheader",
        "-column",
        "-line",
        "-list",
        "-box",
        "-table",
        "-markdown",
        "-batch",
        "-bail",
    ];
    const WITH_VALUE: &[&str] = &["-separator", "-newline", "-nullvalue"];
    let mut positional = Vec::new();
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        i += 1;
        let option = arg
            .strip_prefix('-')
            .map(|o| format!("-{}", o.trim_start_matches('-')));
        match option {
            Some(o) if FLAGS.contains(&o.as_str()) => {}
            Some(o) if WITH_VALUE.contains(&o.as_str()) => i += 1,
            Some(_) => return Change,
            None => positional.push(arg.as_str()),
        }
    }
    let read = positional.len() >= 2
        && !has_shell_mark(positional[0])
        && positional[1..].iter().all(|sql| plain_select(sql));
    if read { Read } else { Change }
}

/// SQL words that may stand before `(` without a function call.
const SQL_PAREN_WORDS: &[&str] = &[
    "in",
    "exists",
    "values",
    "any",
    "all",
    "some",
    "and",
    "or",
    "not",
    "on",
    "from",
    "join",
    "where",
    "as",
    "select",
    "by",
    "when",
    "then",
    "else",
    "case",
    "lateral",
    "over",
    "filter",
    "using",
    "union",
    "intersect",
    "except",
    "is",
    "between",
    "like",
    "ilike",
];
/// SQL words that make a `SELECT` more than a read.
const SQL_WRITE_WORDS: &[&str] = &[
    "into", "update", "share", "lock", "nowait", "insert", "delete", "drop", "truncate", "alter",
    "create", "grant", "revoke", "copy", "execute", "call", "merge", "vacuum", "set", "do",
];

/// Statements that are each a plain `SELECT`: no `INTO`, no `FOR UPDATE`, no function
/// call, no comment, no dollar quote, and no meta command.
fn plain_select(sql: &str) -> bool {
    let lower = sql.to_lowercase();
    if lower.contains(['\\', '$']) || lower.contains("--") || lower.contains("/*") {
        return false;
    }
    let statements: Vec<&str> = lower
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    !statements.is_empty()
        && statements.iter().all(|statement| {
            let words: Vec<&str> = statement
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| !w.is_empty())
                .collect();
            words.first() == Some(&"select")
                && !words.iter().any(|w| SQL_WRITE_WORDS.contains(w))
                && function_calls(statement)
                    .iter()
                    .all(|name| SQL_PAREN_WORDS.contains(&name.as_str()))
        })
}

/// A psql meta command that describes or lists (`\d users`, `\dt`, `\l`, `\conninfo`).
fn psql_meta_read(query: &str) -> bool {
    let Some(rest) = query.trim().strip_prefix('\\') else {
        return false;
    };
    let command = rest.split_whitespace().next().unwrap_or_default();
    let known = command == "conninfo"
        || command == "l"
        || command == "l+"
        || (command.starts_with('d')
            && command.chars().all(|c| c.is_ascii_alphabetic() || c == '+'));
    known && !rest.contains(['\\', ';', '|', '`', '>', '<'])
}
