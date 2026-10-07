//! `apassy completions zsh|bash|fish`: print a shell completion script.
//!
//! The scripts come from the command tables of `apassy help` ([`help::TOPICS`] and
//! [`help::actions`]), so a new command or subcommand appears in them without a second
//! list. They complete the commands, the subcommands, and the main options.

use std::io::{ErrorKind, Write};

use super::args::{Args, usage};
use super::{Outcome, help};

pub const HELP: &str = "\
apassy completions zsh
  Prints a completion script for zsh.
  Install: apassy completions zsh > ~/.zfunc/_apassy, with fpath=(~/.zfunc $fpath) before compinit.
apassy completions bash
  Prints a completion script for bash.
  Install: add this line to ~/.bash_profile: eval \"$(apassy completions bash)\"
apassy completions fish
  Prints a completion script for fish.
  Install: apassy completions fish > ~/.config/fish/completions/apassy.fish
";

/// The main options: short name, long name, whether it takes a value, and its help.
const OPTIONS: &[(Option<&str>, &str, bool, &str)] = &[
    (None, "--json", false, "Machine-readable output"),
    (None, "--socket", true, "The owner socket"),
    (Some("-h"), "--help", false, "Help"),
    (Some("-V"), "--version", false, "The version"),
];

/// Every command of the help table, with `help` itself.
fn commands() -> Vec<&'static str> {
    let mut commands: Vec<&str> = help::TOPICS.split(", ").collect();
    commands.push("help");
    commands
}

/// The commands that take a subcommand, with their subcommands. `help` takes a command.
fn subcommands() -> Vec<(&'static str, Vec<&'static str>)> {
    let mut groups: Vec<_> = commands()
        .into_iter()
        .map(|command| (command, help::actions(command).to_vec()))
        .filter(|(_, actions)| !actions.is_empty())
        .collect();
    groups.push(("help", commands()));
    groups
}

/// The option names, in the order of [`OPTIONS`].
fn option_words() -> Vec<&'static str> {
    OPTIONS
        .iter()
        .flat_map(|(short, long, _, _)| short.iter().copied().chain([*long]))
        .collect()
}

/// Print the script of the shell in the first word.
pub fn run(mut args: Args) -> Outcome {
    let shell = args.required("shell: zsh, bash, or fish")?;
    args.finish()?;
    let script = script(&shell).ok_or_else(|| {
        usage(format!(
            "Unknown shell \"{shell}\". Valid shells: zsh, bash, fish."
        ))
    })?;
    write_script(&mut std::io::stdout().lock(), &script)?;
    Ok(())
}

/// Write the script. A closed pipe, as in `apassy completions bash | head`, is not an error.
fn write_script(out: &mut impl Write, script: &str) -> std::io::Result<()> {
    match out.write_all(script.as_bytes()).and_then(|()| out.flush()) {
        Err(err) if err.kind() == ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

pub(super) fn script(shell: &str) -> Option<String> {
    Some(match shell {
        "zsh" => zsh(),
        "bash" => bash(),
        "fish" => fish(),
        _ => return None,
    })
}

fn zsh() -> String {
    let mut out = String::from(
        "#compdef apassy\n\
# zsh completion for apassy. Made by: apassy completions zsh\n\
_apassy() {\n\
    local i=2 cmd=\"\" cmd_index=0\n\
    if [[ $words[CURRENT-1] == --socket ]]; then\n\
        _files\n\
        return\n\
    fi\n\
    while (( i < CURRENT )); do\n\
        case $words[i] in\n\
            --socket) i=$(( i + 2 )) ;;\n\
            -*) i=$(( i + 1 )) ;;\n\
            *) cmd=$words[i]; cmd_index=$i; break ;;\n\
        esac\n\
    done\n\
    if [[ -z $cmd ]]; then\n\
        if [[ $words[CURRENT] == -* ]]; then\n",
    );
    out.push_str(&format!(
        "            compadd -- {}\n",
        option_words().join(" ")
    ));
    out.push_str("        else\n");
    out.push_str(&format!(
        "            compadd -- {}\n",
        commands().join(" ")
    ));
    out.push_str(
        "        fi\n\
        return\n\
    fi\n\
    if (( CURRENT == cmd_index + 1 )); then\n\
        case $cmd in\n",
    );
    for (command, actions) in subcommands() {
        out.push_str(&format!(
            "            {command}) compadd -- {} && return ;;\n",
            actions.join(" ")
        ));
    }
    // Other words, such as the FILE of `import` or `vault restore`, complete as file names.
    out.push_str(
        "        esac\n\
    fi\n\
    _files\n\
}\n\
if [ \"$funcstack[1]\" = \"_apassy\" ]; then\n\
    _apassy \"$@\"\n\
else\n\
    compdef _apassy apassy\n\
fi\n",
    );
    out
}

fn bash() -> String {
    let mut out = String::from(
        "# bash completion for apassy. Made by: apassy completions bash\n\
_apassy() {\n\
    local cur prev cmd cmd_index i\n\
    COMPREPLY=()\n\
    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n\
    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n\
    if [[ \"$prev\" == --socket ]]; then\n\
        COMPREPLY=( $(compgen -f -- \"$cur\") )\n\
        return 0\n\
    fi\n\
    cmd=\"\"\n\
    cmd_index=0\n\
    for (( i = 1; i < COMP_CWORD; i++ )); do\n\
        case \"${COMP_WORDS[i]}\" in\n\
            --socket) (( i++ )) ;;\n\
            -*) ;;\n\
            *) cmd=\"${COMP_WORDS[i]}\"; cmd_index=$i; break ;;\n\
        esac\n\
    done\n\
    if [[ -z \"$cmd\" ]]; then\n\
        if [[ \"$cur\" == -* ]]; then\n",
    );
    out.push_str(&format!(
        "            COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )\n",
        option_words().join(" ")
    ));
    out.push_str("        else\n");
    out.push_str(&format!(
        "            COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )\n",
        commands().join(" ")
    ));
    out.push_str(
        "        fi\n\
        return 0\n\
    fi\n\
    if (( COMP_CWORD == cmd_index + 1 )); then\n\
        case \"$cmd\" in\n",
    );
    for (command, actions) in subcommands() {
        out.push_str(&format!(
            "            {command}) COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") ) ;;\n",
            actions.join(" ")
        ));
    }
    // With `-o default`, bash completes file names when the function offers nothing.
    out.push_str(
        "        esac\n\
    fi\n\
    return 0\n\
}\n\
complete -o default -F _apassy apassy\n",
    );
    out
}

fn fish() -> String {
    let mut out = String::from("# fish completion for apassy. Made by: apassy completions fish\n");
    for (short, long, takes_value, help) in OPTIONS {
        out.push_str("complete -c apassy");
        if let Some(short) = short {
            out.push_str(&format!(" -s {}", &short[1..]));
        }
        out.push_str(&format!(" -l {}", &long[2..]));
        if *takes_value {
            out.push_str(" -r");
        }
        out.push_str(&format!(" -d '{help}'\n"));
    }
    out.push_str(&format!(
        "complete -c apassy -f -n __fish_use_subcommand -a '{}'\n",
        commands().join(" ")
    ));
    for (command, actions) in subcommands() {
        let words = actions.join(" ");
        // The condition ends once the user has typed one of the subcommands.
        let seen = if command == "help" {
            format!("__fish_seen_subcommand_from help; and not __fish_seen_subcommand_from {words}")
        } else {
            format!(
                "__fish_seen_subcommand_from {command}; and not __fish_seen_subcommand_from {words}"
            )
        };
        out.push_str(&format!("complete -c apassy -f -n '{seen}' -a '{words}'\n"));
    }
    out
}

// The tests write the scripts with `tempfile`, a dependency of the vault feature only.
#[cfg(all(test, feature = "vault"))]
mod tests {
    use super::*;
    use std::process::Command;

    const SHELLS: [&str; 3] = ["zsh", "bash", "fish"];

    fn words(script: &str) -> Vec<&str> {
        script
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .collect()
    }

    #[test]
    fn each_script_has_every_command_and_subcommand_of_the_help_tables() {
        for shell in SHELLS {
            let script = script(shell).unwrap();
            let present = words(&script);
            for command in commands() {
                assert!(present.contains(&command), "{shell}: command {command}");
                for action in help::actions(command) {
                    assert!(
                        present.contains(action),
                        "{shell}: subcommand {command} {action}"
                    );
                }
            }
            for (_, long, _, _) in OPTIONS {
                // Fish writes `-l json`.
                let name = if shell == "fish" { &long[2..] } else { long };
                assert!(script.contains(name), "{shell}: {long}");
            }
        }
        assert!(commands().contains(&"completions"));
        assert!(script("powershell").is_none());
    }

    #[test]
    fn each_subcommand_is_offered_for_its_own_command() {
        let (zsh, bash, fish) = (zsh(), bash(), fish());
        for (command, actions) in subcommands() {
            let list = actions.join(" ");
            assert!(zsh.contains(&format!("{command}) compadd -- {list} && return ;;")));
            assert!(bash.contains(&format!("{command}) COMPREPLY=( $(compgen -W \"{list}\"")));
            assert!(fish.contains(&format!("-a '{list}'")));
        }
        assert!(subcommands().iter().any(|(command, actions)| {
            *command == "completions" && actions == &["zsh", "bash", "fish"]
        }));
    }

    /// Write the script to a temp dir and run a syntax check. `None` when the shell is missing.
    fn syntax_check(shell: &str, args: &[&str]) -> Option<String> {
        let dir = syntax_file(shell);
        let file = dir.path().join(format!("apassy.{shell}"));
        let output = Command::new(shell).args(args).arg(file).output().ok()?;
        Some(if output.status.success() {
            String::new()
        } else {
            String::from_utf8_lossy(&output.stderr).into_owned()
        })
    }

    #[test]
    fn bash_accepts_its_script() {
        let error = syntax_check("bash", &["-n"]).expect("bash is installed");
        assert!(error.is_empty(), "bash -n: {error}");
    }

    #[test]
    fn zsh_accepts_its_script() {
        // The Linux runners of CI have no zsh.
        match syntax_check("zsh", &["-n"]) {
            Some(error) => assert!(error.is_empty(), "zsh -n: {error}"),
            None => eprintln!("zsh is not installed: skipped the zsh syntax check"),
        }
    }

    #[test]
    fn fish_accepts_its_script() {
        match syntax_check("fish", &["--no-execute"]) {
            Some(error) => assert!(error.is_empty(), "fish --no-execute: {error}"),
            None => eprintln!("fish is not installed: skipped the fish syntax check"),
        }
    }

    /// Run the bash function for a command line and return what it offers.
    fn bash_offers(line: &[&str]) -> Vec<String> {
        let dir = syntax_file("bash");
        let words = line
            .iter()
            .map(|word| format!("'{word}'"))
            .collect::<Vec<_>>()
            .join(" ");
        let program = format!(
            "source \"$1\"; COMP_WORDS=({words}); COMP_CWORD={}; _apassy; echo \"${{COMPREPLY[@]}}\"",
            line.len() - 1
        );
        let output = Command::new("bash")
            .args(["-c", &program, "bash"])
            .arg(dir.path().join("apassy.bash"))
            .output()
            .expect("run bash");
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn bash_completes_commands_subcommands_and_options() {
        assert!(bash_offers(&["apassy", "ite"]).contains(&"item".to_owned()));
        let offered = bash_offers(&["apassy", "item", ""]);
        assert!(offered.contains(&"archive".to_owned()));
        assert!(!offered.contains(&"item".to_owned()));
        assert_eq!(
            bash_offers(&["apassy", "--json", "completions", ""]),
            ["zsh", "bash", "fish"]
        );
        assert!(bash_offers(&["apassy", "--so"]).contains(&"--socket".to_owned()));
        assert!(bash_offers(&["apassy", "help", "gr"]).contains(&"grant".to_owned()));
        // Words after the subcommand get no offers, so bash completes file names.
        assert!(bash_offers(&["apassy", "item", "list", ""]).is_empty());
        assert!(bash_offers(&["apassy", "import", ""]).is_empty());
        let output = Command::new("bash")
            .args(["-c", "source \"$1\"; complete -p apassy", "bash"])
            .arg(syntax_file("bash").path().join("apassy.bash"))
            .output()
            .expect("run bash");
        let registered = String::from_utf8_lossy(&output.stdout);
        assert_eq!(registered.trim(), "complete -o default -F _apassy apassy");
    }

    /// A temp dir with the script of a shell in `apassy.SHELL`.
    fn syntax_file(shell: &str) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let file = dir.path().join(format!("apassy.{shell}"));
        std::fs::write(file, script(shell).unwrap()).expect("write script");
        dir
    }

    /// Run the zsh function for a command line with stand-ins for `compadd` and `_files`.
    /// Returns the words offered, and `_files` when it asks for file names. `None` when zsh
    /// is missing.
    fn zsh_offers(line: &[&str]) -> Option<Vec<String>> {
        let dir = syntax_file("zsh");
        let words = line
            .iter()
            .map(|word| format!("'{word}'"))
            .collect::<Vec<_>>()
            .join(" ");
        let program = format!(
            "compdef() {{ :; }}\n\
             _files() {{ print -r -- _files; }}\n\
             compadd() {{\n\
                 [[ $1 == -- ]] && shift\n\
                 local word found=1\n\
                 for word in \"$@\"; do\n\
                     if [[ $word == ${{words[CURRENT]}}* ]]; then print -r -- $word; found=0; fi\n\
                 done\n\
                 return found\n\
             }}\n\
             source \"$1\"\n\
             words=({words}); CURRENT={}\n\
             _apassy",
            line.len()
        );
        let output = Command::new("zsh")
            .args(["-f", "-c", &program, "zsh"])
            .arg(dir.path().join("apassy.zsh"))
            .output()
            .ok()?;
        assert!(
            output.status.success() || output.stderr.is_empty(),
            "zsh: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        )
    }

    #[test]
    fn zsh_completes_file_names_where_no_subcommand_fits() {
        let Some(offered) = zsh_offers(&["apassy", "item", ""]) else {
            eprintln!("zsh is not installed: skipped the zsh completion check");
            return;
        };
        assert!(offered.contains(&"archive".to_owned()));
        assert!(!offered.contains(&"_files".to_owned()));
        assert!(
            zsh_offers(&["apassy", "ite"])
                .unwrap()
                .contains(&"item".to_owned())
        );
        for line in [
            &["apassy", "import", ""][..],
            &["apassy", "vault", "restore", ""],
            &["apassy", "--json", "decisions", "export", ""],
            &["apassy", "--socket", ""],
        ] {
            assert_eq!(zsh_offers(line).unwrap(), ["_files"], "{line:?}");
        }
    }

    /// The bash line of the help, as the docs write it too.
    const BASH_INSTALL: &str = "eval \"$(apassy completions bash)\"";

    #[test]
    fn the_documented_bash_line_works_in_the_bash_of_macos() {
        let docs = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/operations/cli.md"
        ))
        .expect("read cli.md");
        assert!(HELP.contains(&format!("~/.bash_profile: {BASH_INSTALL}")));
        assert!(docs.contains(&format!("\n{BASH_INSTALL}\n")));
        assert!(!HELP.contains("source <(apassy") && !docs.contains("source <(apassy"));

        // A stand-in `apassy` prints the script. macOS ships bash 3.2 as /bin/bash, where
        // `source <(...)` reads nothing.
        let dir = syntax_file("bash");
        let stand_in = dir.path().join("apassy");
        std::fs::write(
            &stand_in,
            format!(
                "#!/bin/sh\ncat '{}'\n",
                dir.path().join("apassy.bash").display()
            ),
        )
        .expect("write stand-in");
        std::fs::set_permissions(
            &stand_in,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("chmod stand-in");
        let output = Command::new("/bin/bash")
            .args(["-c", &format!("{BASH_INSTALL}\ncomplete -p apassy")])
            .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
            .output()
            .expect("run /bin/bash");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "complete -o default -F _apassy apassy",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A writer that fails like a pipe whose reader is gone, or like a full disk.
    struct Failing(ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_pipe_is_not_an_error() {
        let mut out = Vec::new();
        write_script(&mut out, "script\n").unwrap();
        assert_eq!(out, b"script\n");
        assert!(write_script(&mut Failing(ErrorKind::BrokenPipe), "script\n").is_ok());
        assert!(write_script(&mut Failing(ErrorKind::StorageFull), "script\n").is_err());
    }
}
