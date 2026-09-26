//! Remembered command patterns (ADR 0009 step 1, ADR 0010).
//!
//! A pattern generalizes a command by argument type only:
//!
//! - `<file>`: a path inside the project directory.
//! - `<number>`: digits, with an optional decimal part.
//! - `<string>`: a quoted argument. In an argument list without a shell, an argument
//!   with a space or a shell character counts as a quoted string.
//!
//! Every other word stays literal: the program, its subcommand, options, names, and
//! any word that the shell expands (`$NAME`, globs, `~`). A word that the generalizer
//! does not understand stays literal. So two commands have the same pattern only when
//! they differ in inert arguments of the three types.
//!
//! Narrow rules:
//!
//! - The program and the next word stay literal, also when the next word is a file.
//!   So `node scripts/seed.js` stays literal.
//! - A command with a program that runs code from its arguments (a shell, an
//!   interpreter, `awk`, `jq`, or an SQL client) keeps every file and string literal.
//! - A path with a hidden component (`.env`, `.git/config`), a path outside the
//!   project, and a word with `:` or `@` stay literal.
//! - A shell script (`sh -c TEXT`) is split into words. A script with a line break, a
//!   backslash, a comment, a here-document, or a command substitution stays literal.

use std::path::{Component, Path, PathBuf};

use serde::Serialize;

/// The largest template that Apassy stores. A longer command cannot be remembered.
pub const MAX_TEMPLATE_BYTES: usize = 8192;

/// Shells that run a command string.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// Programs that run code or queries from their arguments, or read the environment.
const CODE_RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "node",
    "nodejs",
    "deno",
    "bun",
    "tsx",
    "ts-node",
    "vite-node",
    "python",
    "python2",
    "python3",
    "pypy",
    "pypy3",
    "ruby",
    "perl",
    "php",
    "lua",
    "luajit",
    "osascript",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "jq",
    "yq",
    "psql",
    "mysql",
    "sqlite3",
    "mongosh",
    "mongo",
    "redis-cli",
    "eval",
    "source",
    ".",
];

/// File name extensions that make a single name (without `/`) a file.
const FILE_EXTENSIONS: &[&str] = &[
    "md", "mdx", "txt", "rst", "json", "jsonc", "json5", "yaml", "yml", "toml", "ini", "cfg",
    "conf", "lock", "log", "csv", "tsv", "xml", "html", "htm", "css", "scss", "sass", "less", "js",
    "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "vue", "svelte", "astro", "rs", "py", "rb",
    "go", "java", "kt", "swift", "c", "h", "cc", "cpp", "hpp", "m", "mm", "cs", "sql", "sh",
    "graphql", "gql", "prisma", "proto", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "pdf",
    "snap", "map", "patch", "diff",
];

/// One element of a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Token {
    /// A word that must be the same. For a script word, this is the source text.
    Lit(String),
    /// A shell operator such as `|`, `&&`, `;`, or `>`.
    Op(String),
    File,
    Number,
    Str,
    /// The words of a `sh -c` script.
    Script(Vec<Token>),
}

/// Where the command runs. Both paths are canonical.
#[derive(Debug, Clone, Copy)]
pub struct Place<'a> {
    pub project_dir: &'a Path,
    pub cwd: &'a Path,
}

/// A generalized command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub tokens: Vec<Token>,
}

impl Pattern {
    /// Canonical text for storage and comparison. Two commands match when their
    /// templates are equal.
    pub fn template(&self) -> String {
        serde_json::to_string(&self.tokens).unwrap_or_default()
    }

    /// Text for the owner, for example `git log -n <number> -- <file>`.
    pub fn display(&self) -> String {
        display_tokens(&self.tokens, false)
    }
}

/// Generalize an argument list (ADR 0010). `None` when the template is too long.
pub fn generalize(argv: &[String], place: Place<'_>) -> Option<Pattern> {
    let tokens = generalize_argv(argv, place);
    let pattern = Pattern { tokens };
    (pattern.template().len() <= MAX_TEMPLATE_BYTES).then_some(pattern)
}

fn generalize_argv(argv: &[String], place: Place<'_>) -> Vec<Token> {
    let program = argv.first().map(|arg| base_name(arg)).unwrap_or_default();
    if SHELLS.contains(&program.as_str())
        && let Some(pos) = argv.iter().position(|arg| arg == "-c" || arg == "-lc")
        && let Some(script) = argv.get(pos + 1)
    {
        // The shell, its options, and any arguments after the script stay literal.
        let mut tokens: Vec<Token> = argv[..=pos].iter().cloned().map(Token::Lit).collect();
        tokens.push(match split_script(script) {
            Some(pieces) => Token::Script(generalize_script(&pieces, place)),
            None => Token::Lit(script.clone()),
        });
        tokens.extend(argv[pos + 2..].iter().cloned().map(Token::Lit));
        return tokens;
    }
    // Without a shell, no word expands. A word that needs quotes in a shell is a string.
    let words: Vec<Word> = argv
        .iter()
        .map(|arg| Word {
            raw: arg.clone(),
            value: arg.clone(),
            quoting: if needs_quotes(arg) {
                Quoting::Quoted
            } else {
                Quoting::Plain
            },
            expands: false,
            attached: false,
        })
        .collect();
    generalize_simple(&words, place, true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quoting {
    /// No quotes.
    Plain,
    /// The whole word is one quoted part.
    Quoted,
    /// Quoted and plain parts together, for example `--name='x y'`.
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Word {
    /// Source text, with quotes.
    raw: String,
    /// Text after quote removal.
    value: String,
    quoting: Quoting,
    /// The shell can change the word: `$`, globs, `~`, `!`, or braces.
    expands: bool,
    /// The word touches a shell operator, for example `2>&1`.
    attached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Word(Word),
    Op(String),
}

/// Split a script into words and operators. `None` for syntax that this lexer does
/// not model. Such a script stays literal.
fn split_script(script: &str) -> Option<Vec<Piece>> {
    if script.contains('\n')
        || script.contains('\r')
        || script.contains('\\')
        || script.contains('`')
        || script.contains("$(")
        || script.contains("<<")
    {
        return None;
    }
    let mut pieces = Vec::new();
    let mut chars = script.chars().peekable();
    let mut word: Option<Word> = None;
    // The last piece was an operator with no space after it.
    let mut after_op = false;
    let finish = |word: &mut Option<Word>, pieces: &mut Vec<Piece>| {
        if let Some(word) = word.take() {
            pieces.push(Piece::Word(word));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                finish(&mut word, &mut pieces);
                after_op = false;
            }
            '|' | '&' | ';' | '<' | '>' | '(' | ')' => {
                let adjacent = word.is_some();
                finish(&mut word, &mut pieces);
                let mut op = c.to_string();
                while let Some(next) = chars.peek().copied() {
                    if "|&<>".contains(next) {
                        op.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                // A word that touches a redirect can be a file descriptor (`2>&1`).
                let redirect = op.contains('<') || op.contains('>');
                if redirect
                    && adjacent
                    && let Some(Piece::Word(last)) = pieces.last_mut()
                {
                    last.attached = true;
                }
                pieces.push(Piece::Op(op));
                after_op = redirect;
            }
            '#' if word.is_none() => return None,
            '\'' | '"' => {
                let current = word.get_or_insert_with(|| new_word(after_op));
                let mut part = String::new();
                let mut closed = false;
                for inner in chars.by_ref() {
                    if inner == c {
                        closed = true;
                        break;
                    }
                    if c == '"' && matches!(inner, '$' | '!') {
                        current.expands = true;
                    }
                    part.push(inner);
                }
                if !closed {
                    return None;
                }
                current.quoting = match current.quoting {
                    Quoting::Plain if current.raw.is_empty() => Quoting::Quoted,
                    _ => Quoting::Mixed,
                };
                current.raw.push(c);
                current.raw.push_str(&part);
                current.raw.push(c);
                current.value.push_str(&part);
            }
            _ => {
                let current = word.get_or_insert_with(|| new_word(after_op));
                if matches!(c, '$' | '*' | '?' | '[' | ']' | '{' | '}' | '!')
                    || (c == '~' && current.raw.is_empty())
                {
                    current.expands = true;
                }
                if current.quoting == Quoting::Quoted {
                    current.quoting = Quoting::Mixed;
                }
                current.raw.push(c);
                current.value.push(c);
            }
        }
    }
    finish(&mut word, &mut pieces);
    Some(pieces)
}

fn new_word(attached: bool) -> Word {
    Word {
        raw: String::new(),
        value: String::new(),
        quoting: Quoting::Plain,
        expands: false,
        attached,
    }
}

/// Generalize each simple command of a script. Operators stay literal. After a
/// redirect operator, the next word is a target, not a program. After `cd`, a relative
/// path does not start in the working directory, so later files stay literal.
fn generalize_script(pieces: &[Piece], place: Place<'_>) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut segment: Vec<Word> = Vec::new();
    let mut files = true;
    let mut flush = |segment: &mut Vec<Word>, tokens: &mut Vec<Token>| {
        let changes_dir = segment.iter().any(|word| {
            word.quoting == Quoting::Plain && matches!(word.value.as_str(), "cd" | "pushd" | "popd")
        });
        files &= !changes_dir;
        tokens.extend(generalize_simple(segment, place, files));
        segment.clear();
    };
    for piece in pieces {
        match piece {
            Piece::Word(word) => segment.push(word.clone()),
            Piece::Op(op) => {
                if op.contains('<') || op.contains('>') {
                    // A redirect belongs to the current simple command.
                    segment.push(Word {
                        raw: op.clone(),
                        value: String::new(),
                        quoting: Quoting::Mixed,
                        expands: true,
                        attached: true,
                    });
                    continue;
                }
                flush(&mut segment, &mut tokens);
                tokens.push(Token::Op(op.clone()));
            }
        }
    }
    flush(&mut segment, &mut tokens);
    tokens
}

/// One simple command: assignments, the program, the subcommand, and arguments.
/// `files` is false when a relative path does not start in the working directory.
fn generalize_simple(words: &[Word], place: Place<'_>, files: bool) -> Vec<Token> {
    let runs_code = words.iter().any(|word| {
        word.quoting == Quoting::Plain
            && !word.expands
            && CODE_RUNNERS.contains(&base_name(&word.value).as_str())
    });
    let mut tokens = Vec::with_capacity(words.len());
    // Program and subcommand positions, after `NAME=value` assignments.
    let mut position = 0usize;
    for word in words {
        let literal = Token::Lit(word.raw.clone());
        let assignment = position == 0 && is_assignment(&word.value);
        if assignment || word.expands || word.attached || word.quoting == Quoting::Mixed {
            tokens.push(literal);
            if !assignment && !word.value.is_empty() {
                position += 1;
            }
            continue;
        }
        let fixed = position == 0 || (position == 1 && !word.value.starts_with('-'));
        position += 1;
        if fixed {
            tokens.push(literal);
            continue;
        }
        tokens.push(classify(word, place, runs_code, files).unwrap_or(literal));
    }
    tokens
}

/// The type of an inert argument, or `None` to keep it literal.
fn classify(word: &Word, place: Place<'_>, runs_code: bool, files: bool) -> Option<Token> {
    let value = word.value.as_str();
    if is_number(value) {
        return Some(Token::Number);
    }
    if runs_code {
        return None;
    }
    if looks_like_path(value) {
        return (files && file_in_project(value, place)).then_some(Token::File);
    }
    let string = word.quoting == Quoting::Quoted
        && !value.is_empty()
        && !value.starts_with('-')
        && !value.contains("://");
    string.then_some(Token::Str)
}

fn is_number(value: &str) -> bool {
    let mut parts = value.splitn(2, '.');
    let whole = parts.next().unwrap_or_default();
    let digits =
        |part: &str| (1..=18).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit());
    digits(whole) && parts.next().is_none_or(digits)
}

fn looks_like_path(value: &str) -> bool {
    value.contains('/')
        || value.starts_with('.')
        || value.starts_with('~')
        || has_file_extension(value)
}

fn has_file_extension(value: &str) -> bool {
    value
        .rsplit_once('.')
        .is_some_and(|(stem, ext)| !stem.is_empty() && FILE_EXTENSIONS.contains(&ext))
}

/// A path inside the project, by text only. Hidden components, hosts, `user@host`,
/// and `host:path` stay literal.
fn file_in_project(value: &str, place: Place<'_>) -> bool {
    let safe = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._/+,=-".contains(&b));
    if !safe || value.is_empty() {
        return false;
    }
    let relative = value.trim_start_matches("./");
    let mut parts = relative.split('/').filter(|part| !part.is_empty());
    if let Some(first) = parts.clone().next()
        && !value.starts_with('/')
        && first != "."
        && first != ".."
        && first.contains('.')
        && value.contains('/')
    {
        // `example.com/path` is a host, not a directory.
        return false;
    }
    if parts.any(|part| part.starts_with('.') && part != "." && part != "..") {
        return false;
    }
    if !value.contains('/') && !has_file_extension(value) && value != "." {
        return false;
    }
    let base = if value.starts_with('/') {
        PathBuf::from("/")
    } else {
        place.cwd.to_path_buf()
    };
    let mut resolved = PathBuf::new();
    for component in base.join(value).components() {
        match component {
            Component::ParentDir => {
                if !resolved.pop() {
                    return false;
                }
            }
            Component::CurDir => {}
            other => resolved.push(other),
        }
    }
    resolved.starts_with(place.project_dir)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
    })
}

fn base_name(program: &str) -> String {
    program.rsplit('/').next().unwrap_or(program).to_lowercase()
}

fn needs_quotes(arg: &str) -> bool {
    arg.is_empty()
        || arg
            .chars()
            .any(|c| c.is_whitespace() || "'\"\\$`|&;<>()*?[]{}!#~".contains(c))
}

/// A literal of a script is shell source. A literal of an argument list is quoted
/// when a shell would need quotes.
fn display_tokens(tokens: &[Token], script: bool) -> String {
    tokens
        .iter()
        .map(|token| match token {
            Token::Lit(text) => {
                if !script && needs_quotes(text) {
                    format!("'{}'", text.replace('\'', "'\\''"))
                } else {
                    text.clone()
                }
            }
            Token::Op(op) => op.clone(),
            Token::File => "<file>".to_owned(),
            Token::Number => "<number>".to_owned(),
            Token::Str => "<string>".to_owned(),
            Token::Script(inner) => format!("'{}'", display_tokens(inner, true)),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    fn shown(words: &[&str]) -> String {
        let project = Path::new("/work/app");
        let place = Place {
            project_dir: project,
            cwd: project,
        };
        generalize(&argv(words), place).expect("pattern").display()
    }

    fn template(words: &[&str], cwd: &str) -> String {
        let place = Place {
            project_dir: Path::new("/work/app"),
            cwd: Path::new(cwd),
        };
        generalize(&argv(words), place).expect("pattern").template()
    }

    #[test]
    fn arguments_generalize_by_type_only() {
        assert_eq!(
            shown(&["git", "log", "-n", "20", "--", "src/main.rs"]),
            "git log -n <number> -- <file>"
        );
        assert_eq!(
            shown(&["git", "commit", "-m", "fix the login form"]),
            "git commit -m <string>"
        );
        assert_eq!(
            shown(&["npx", "vitest", "run", "src/lib/auth.test.ts"]),
            "npx vitest run <file>"
        );
        // Names, branches, hosts, URLs, and options stay literal.
        assert_eq!(
            shown(&["git", "push", "origin", "feature-x"]),
            "git push origin feature-x"
        );
        assert_eq!(
            shown(&["curl", "-s", "https://api.example.com/v1/items"]),
            "curl -s https://api.example.com/v1/items"
        );
        assert_eq!(
            shown(&["curl", "-s", "example.com/x"]),
            "curl -s example.com/x"
        );
        assert_eq!(
            shown(&["ping", "-c", "1", "127.0.0.1"]),
            "ping -c <number> 127.0.0.1"
        );
        assert_eq!(
            shown(&["scp", "-q", "a.txt", "host:a.txt"]),
            "scp -q <file> host:a.txt"
        );
    }

    #[test]
    fn program_and_subcommand_stay_literal() {
        assert_eq!(
            shown(&["node", "scripts/seed.js"]),
            "node scripts/seed.js",
            "the script of an interpreter stays literal"
        );
        assert_eq!(shown(&["cat", "src/a.ts"]), "cat src/a.ts");
        assert_eq!(
            shown(&["head", "-n", "5", "src/a.ts"]),
            "head -n <number> <file>"
        );
        // A code runner keeps files and strings literal anywhere in the command.
        assert_eq!(
            shown(&["python3", "-m", "pytest", "tests/api"]),
            "python3 -m pytest tests/api"
        );
        assert_eq!(
            shown(&["timeout", "30", "node", "scripts/x.js"]),
            "timeout 30 node scripts/x.js"
        );
        assert_eq!(
            shown(&["psql", "-c", "select * from users"]),
            "psql -c 'select * from users'"
        );
    }

    #[test]
    fn hidden_and_outside_paths_stay_literal() {
        assert_eq!(shown(&["git", "add", ".env"]), "git add .env");
        assert_eq!(
            shown(&["git", "diff", "config/.env.local"]),
            "git diff config/.env.local"
        );
        assert_eq!(shown(&["wc", "-l", "/etc/passwd"]), "wc -l /etc/passwd");
        assert_eq!(shown(&["wc", "-l", "../other/x.rs"]), "wc -l ../other/x.rs");
        assert_eq!(shown(&["wc", "-l", "/work/app/x.rs"]), "wc -l <file>");
        assert_eq!(shown(&["wc", "-l", "~/x.rs"]), "wc -l '~/x.rs'");
        // A name without a known extension is a word, not a file.
        assert_eq!(shown(&["wc", "-l", "example.com"]), "wc -l example.com");
        assert_eq!(shown(&["wc", "-l", "README.md"]), "wc -l <file>");
    }

    #[test]
    fn working_directory_decides_inside_the_project() {
        let inside = template(&["wc", "-l", "../x.rs"], "/work/app/src");
        let outside = template(&["wc", "-l", "../x.rs"], "/work/app");
        assert!(inside.contains("\"File\""), "{inside}");
        assert!(outside.contains("../x.rs"), "{outside}");
    }

    #[test]
    fn shell_scripts_are_split_into_words() {
        assert_eq!(
            shown(&["bash", "-lc", "sed -n '1,80p' src/a.ts | head -n 5"]),
            "bash -lc 'sed -n <string> <file> | head -n <number>'"
        );
        assert_eq!(
            shown(&["sh", "-c", "npm test 2>&1 | tail -n 40"]),
            "sh -c 'npm test 2 >& 1 | tail -n <number>'"
        );
        // Expansions, globs, and variables stay literal.
        assert_eq!(
            shown(&["sh", "-c", "echo $DEMO_KEY | base64"]),
            "sh -c 'echo $DEMO_KEY | base64'"
        );
        assert_eq!(
            shown(&["sh", "-c", "ls src/*.ts \"$HOME/x.md\""]),
            "sh -c 'ls src/*.ts \"$HOME/x.md\"'"
        );
        // Unsupported syntax keeps the whole script literal.
        for script in [
            "cat <<EOF\nx\nEOF",
            "echo $(cat .env)",
            "echo `id`",
            "echo a\\ b",
            "# note",
            "echo 'open",
        ] {
            let pattern = generalize(
                &argv(&["sh", "-c", script]),
                Place {
                    project_dir: Path::new("/work/app"),
                    cwd: Path::new("/work/app"),
                },
            )
            .expect("pattern");
            assert_eq!(pattern.tokens[2], Token::Lit(script.to_owned()), "{script}");
        }
        // A redirect target is an argument. A file in the project generalizes.
        assert_eq!(
            shown(&["sh", "-c", "npm run build > build.log"]),
            "sh -c 'npm run build > <file>'"
        );
        // Each simple command keeps its own program and subcommand.
        assert_eq!(
            shown(&["sh", "-c", "rg -n 'fn main' lib.rs; git status"]),
            "sh -c 'rg -n <string> <file> ; git status'"
        );
        // Assignments stay literal and do not count as the program.
        assert_eq!(
            shown(&["sh", "-c", "NODE_ENV=test npx jest src/a.test.ts"]),
            "sh -c 'NODE_ENV=test npx jest <file>'"
        );
        // After `cd`, relative files stay literal.
        assert_eq!(
            shown(&["sh", "-c", "wc -l a.rs && cd .. && wc -l a.rs"]),
            "sh -c 'wc -l <file> && cd .. && wc -l a.rs'"
        );
    }

    #[test]
    fn different_literals_give_different_templates() {
        let base = template(&["git", "log", "-n", "5"], "/work/app");
        assert_eq!(base, template(&["git", "log", "-n", "500"], "/work/app"));
        assert_ne!(
            base,
            template(&["git", "log", "-n", "5", "-p"], "/work/app")
        );
        assert_ne!(base, template(&["git", "reflog", "-n", "5"], "/work/app"));
        // An operator is not the same as a quoted word.
        assert_ne!(
            template(&["sh", "-c", "echo a | wc"], "/work/app"),
            template(&["sh", "-c", "echo a '|' wc"], "/work/app")
        );
        // A long command has no pattern.
        let long = vec!["x".repeat(MAX_TEMPLATE_BYTES)];
        assert!(
            generalize(
                &long,
                Place {
                    project_dir: Path::new("/work/app"),
                    cwd: Path::new("/work/app"),
                }
            )
            .is_none()
        );
    }
}
