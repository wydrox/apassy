//! `apassy team ...`: the team command line (`crate::cli`) with the first word removed
//! (plan D8, 3F). The settings directory stays `~/.config/apassy-team` for one release.
//! The `apassy-team` binary stays one release as an alias with a deprecation line.

/// The line that `apassy-team` prints to stderr on a terminal.
pub const DEPRECATION_LINE: &str =
    "apassy-team: this name goes away in the next version. Use `apassy team` with the same words.";
/// With `1`, `apassy-team` prints `DEPRECATION_LINE` also when stderr is not a terminal.
pub const DEPRECATION_ENV: &str = "APASSY_TEAM_DEPRECATION";

/// Runs `apassy team <args>` and returns the exit code.
pub fn run(args: Vec<String>) -> i32 {
    crate::cli::main_as(crate::cli::Program::NodeTeam, args)
}
