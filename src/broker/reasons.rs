//! The words of a decision (ADR 0046): one short reason for a History row and one
//! sentence for the question title and the "Why" of a past decision. The tables are
//! closed: the words come from the reason kind, the rule flags, and the refusal code,
//! never from request text.

use super::prompts::{FLAG_AMBIGUOUS, FLAG_UNVERIFIED};
use super::route_diagnostics::ReasonKind;
use super::shell_risk::INJECTION_FLAG;
use crate::vault::DecisionWhy;

/// The words of one reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Words {
    /// The History row: at most 30 characters, no full stop. Empty for
    /// [`ReasonKind::Other`].
    pub short: &'static str,
    /// The question title and the "Why" of a past decision: one sentence.
    pub line: &'static str,
}

const fn words_of(short: &'static str, line: &'static str) -> Words {
    Words { short, line }
}

/// The rule flags in priority order: the first one of a run names it.
const FLAGS: [(&str, Words); 17] = [
    (
        "secret_output",
        words_of(
            "Could print the secret",
            "The command could print the secret.",
        ),
    ),
    (
        "foreign_host",
        words_of(
            "Secret to an unknown host",
            "The secret would go to an unknown host.",
        ),
    ),
    (
        "db_host_from_command",
        words_of(
            "Own database host",
            "The command names its own database host.",
        ),
    ),
    (
        "remote_code",
        words_of(
            "Runs code from the internet",
            "The command runs code from the internet.",
        ),
    ),
    (
        "data_loss",
        words_of("Could delete data", "The command could delete data."),
    ),
    (
        "irreversible",
        words_of("Cannot be undone", "The command cannot be undone."),
    ),
    (
        "production",
        words_of("Targets production", "The command targets production."),
    ),
    (
        "privilege",
        words_of(
            "Asks for admin rights",
            "The command asks for admin rights.",
        ),
    ),
    (
        "system_change",
        words_of("Changes system files", "The command changes system files."),
    ),
    (
        "real_recipient",
        words_of("Sends to real people", "The command sends to real people."),
    ),
    (
        "remote_access",
        words_of(
            "Reaches a remote machine",
            "The command reaches into a remote machine.",
        ),
    ),
    (
        "new_dependency",
        words_of(
            "Installs an unknown package",
            "The command installs an unknown package.",
        ),
    ),
    (
        "ask_owner",
        words_of("A rule asks you", "A rule asks you about this command."),
    ),
    (
        "hook_channel",
        words_of(
            "Touches the prompt hook",
            "The command touches the agent's prompt hook.",
        ),
    ),
    (
        "rule_pack_error",
        words_of("Rule pack did not load", "A rule pack did not load."),
    ),
    (
        FLAG_UNVERIFIED,
        words_of(
            "Prompt not confirmed",
            "Apassy could not confirm your prompt.",
        ),
    ),
    (
        FLAG_AMBIGUOUS,
        words_of(
            "Unclear agent session",
            "Apassy could not tell which agent session asked.",
        ),
    ),
];

/// A flag that no table names.
const OTHER_FLAG: Words = words_of("Flagged command", "A safety rule flagged this run.");

/// The injection flag reads last: another flag of the same run says more.
const INJECTION: Words = words_of(
    "Text mentions the bouncer",
    "The request text mentions the bouncer or an approval.",
);

/// Refusals by a check, by their wire code.
const CODES: [(&str, Words); 10] = [
    (
        "not_granted",
        words_of(
            "Not for this agent",
            "This agent may not use this credential.",
        ),
    ),
    (
        "item_archived",
        words_of("Archived", "This credential is archived."),
    ),
    (
        "review_required",
        words_of(
            "Waits for your review",
            "This credential waits for your review.",
        ),
    ),
    (
        "needs_field",
        words_of(
            "No field for agents",
            "No field of this credential is set for agents.",
        ),
    ),
    (
        "invalid_request",
        words_of(
            "Unreadable request",
            "The agent sent a request Apassy could not read.",
        ),
    ),
    (
        "no_code",
        words_of(
            "No one-time code",
            "This credential has no usable one-time code.",
        ),
    ),
    (
        "invalid_code",
        words_of(
            "No one-time code",
            "This credential has no usable one-time code.",
        ),
    ),
    (
        "duplicate_env_name",
        words_of(
            "Variable name used twice",
            "Two credentials use the same variable name.",
        ),
    ),
    (
        "refused",
        words_of("Wrong site", "The page is not a site of this credential."),
    ),
    (
        "lease_failed",
        words_of(
            "Temporary credentials",
            "Apassy cannot make its temporary credentials yet.",
        ),
    ),
];

/// The short reason of a kind for the History row.
fn short_of(reason: ReasonKind) -> &'static str {
    match reason {
        ReasonKind::ModelAllowed => "Judged safe",
        ReasonKind::RememberedAnswer => "Covered by your rule",
        ReasonKind::RememberedPattern => "Approved before",
        ReasonKind::MissingTask => "No task from the agent",
        ReasonKind::LowTaskMatch => "May not fit your task",
        ReasonKind::ModelUnsure => "May not be safe",
        ReasonKind::ModelUnavailable => "Bouncer brain off",
        ReasonKind::ModelTimeout => "Bouncer brain too slow",
        ReasonKind::HookUnverified => "Prompt not confirmed",
        ReasonKind::HookAmbiguous => "Unclear agent session",
        ReasonKind::HookFlags => OTHER_FLAG.short,
        ReasonKind::NotProject => "Not a project folder",
        ReasonKind::AlwaysAsk => "Always ask",
        ReasonKind::Production => "Production credential",
        ReasonKind::ForeignHost => "Unknown host",
        ReasonKind::ForeignProject => "Another project's credential",
        ReasonKind::MissingDeclaration => "No environment set",
        ReasonKind::UnfitAnswer => "Rule doesn't cover it",
        ReasonKind::OneTimeCode => "One-time code",
        ReasonKind::AccessCheck => "Refused",
        ReasonKind::CloudAgent => "Remote agent",
        ReasonKind::BrowserFill => "Browser fill",
        ReasonKind::Connector => "Connector",
        ReasonKind::Other => "",
    }
}

/// The flags of a run in the order of the tables: known flags first, then one entry
/// for every unknown name, then the injection flag.
fn ordered_flags(flags: &[String]) -> Vec<Words> {
    let mut out: Vec<Words> = FLAGS
        .iter()
        .filter(|(name, _)| flags.iter().any(|flag| flag == name))
        .map(|(_, words)| *words)
        .collect();
    if flags
        .iter()
        .any(|flag| flag != INJECTION_FLAG && !FLAGS.iter().any(|(name, _)| flag == name))
    {
        out.push(OTHER_FLAG);
    }
    if flags.iter().any(|flag| flag == INJECTION_FLAG) {
        out.push(INJECTION);
    }
    out
}

/// The words of a decision. `flags` matter for [`ReasonKind::HookFlags`], `code` for
/// [`ReasonKind::AccessCheck`].
pub fn words(reason: ReasonKind, flags: &[String], code: &str) -> Words {
    match reason {
        ReasonKind::HookFlags => ordered_flags(flags).first().copied().unwrap_or(OTHER_FLAG),
        ReasonKind::AccessCheck => CODES.iter().find(|(name, _)| *name == code).map_or(
            words_of(short_of(reason), reason.headline()),
            |(_, words)| *words,
        ),
        _ => words_of(short_of(reason), reason.headline()),
    }
}

/// The injection sentence in a text that an agent reads: it does not name the words that
/// the rule reacts to.
pub const INJECTION_FOR_AGENT: &str = "A safety rule flagged the request text.";

/// `text` as an agent reads it. The owner's window keeps the full sentence.
#[must_use]
pub fn for_agent(text: &str) -> String {
    text.replace(INJECTION.line, INJECTION_FOR_AGENT)
}

/// The question's why text for a flagged run: the sentence of each flag in order. How
/// long a run like it asks ([`every_time`]) is for the owner's window only: the desktop
/// draws it, and it is never part of the stored why, the refusal text, or the card.
pub fn flags_sentence(flags: &[String]) -> String {
    ordered_flags(flags)
        .into_iter()
        .map(|words| words.line)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The sentence for a decision that no answer of the owner can change; `None` when an
/// answer can.
pub fn every_time(reason: ReasonKind, flags: &[String]) -> Option<&'static str> {
    let has = |name: &str| flags.iter().any(|flag| flag == name);
    if flags
        .iter()
        .any(|flag| ![FLAG_UNVERIFIED, FLAG_AMBIGUOUS, INJECTION_FLAG].contains(&flag.as_str()))
    {
        return Some("A command like this asks every time.");
    }
    if has(FLAG_UNVERIFIED) {
        return Some("Apassy asks until it can confirm your prompt.");
    }
    if has(FLAG_AMBIGUOUS) {
        return Some("Apassy asks while it cannot tell which session asked.");
    }
    if has(INJECTION_FLAG) {
        return Some("Apassy asks while the text says this.");
    }
    match reason {
        ReasonKind::MissingTask => Some("Apassy asks until the agent sends your task."),
        ReasonKind::NotProject => Some("Apassy remembers nothing outside a project folder."),
        ReasonKind::Production => Some("This production credential asks every time."),
        ReasonKind::CloudAgent => Some("A cloud agent asks every time."),
        _ => None,
    }
}

/// The reason kind of a stored decision. A row of an older version has no words: its
/// kind comes from `decided_by` (`model`, `pattern`, `answer`, `rule`, `owner`,
/// `no_answer`) and its flags.
pub fn kind_of(why: &DecisionWhy, decided_by: &str, flags: &[String]) -> ReasonKind {
    if let Some(kind) = ReasonKind::parse(&why.reason) {
        return kind;
    }
    match decided_by {
        "model" => ReasonKind::ModelAllowed,
        "pattern" => ReasonKind::RememberedPattern,
        "answer" => ReasonKind::RememberedAnswer,
        "rule" => ReasonKind::AccessCheck,
        _ if flags.iter().any(|flag| flag == FLAG_UNVERIFIED) => ReasonKind::HookUnverified,
        _ if flags.iter().any(|flag| flag == FLAG_AMBIGUOUS) => ReasonKind::HookAmbiguous,
        _ if !flags.is_empty() => ReasonKind::HookFlags,
        _ => ReasonKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Every flag name of the tables, the injection flag, and one unknown name.
    fn every_flag() -> Vec<String> {
        let mut names: Vec<String> = FLAGS.iter().map(|(name, _)| (*name).to_owned()).collect();
        names.push(INJECTION_FLAG.to_owned());
        names.push("some_new_flag".to_owned());
        names
    }

    fn keeps_the_text_rules(words: Words, what: &str) {
        let short = words.short;
        assert!(short.chars().count() <= 30, "{what}: {short}");
        assert!(
            !short.contains('.') && !short.contains('_'),
            "{what}: {short}"
        );
        let line = words.line;
        assert!(line.ends_with('.'), "{what}: {line}");
        assert!(!line.contains('_'), "{what}: {line}");
        // The cloud card's headline has two sentences, as the cloud question shows it.
        if what != "CloudAgent" {
            assert!(line.chars().count() <= 64, "{what}: {line}");
        }
        for name in every_flag().iter().filter(|name| name.contains('_')) {
            assert!(!line.contains(name.as_str()), "{what}: {line}");
        }
    }

    #[test]
    fn every_kind_flag_and_code_has_words_that_keep_the_text_rules() {
        for kind in ReasonKind::ALL {
            let words = words(kind, &[], "");
            keeps_the_text_rules(words, &format!("{kind:?}"));
            assert_eq!(
                words.short.is_empty(),
                kind == ReasonKind::Other,
                "{kind:?}"
            );
        }
        for flag in every_flag() {
            let words = words(ReasonKind::HookFlags, &flags(&[flag.as_str()]), "");
            keeps_the_text_rules(words, &flag);
            assert!(!words.short.is_empty(), "{flag}");
        }
        for (code, _) in CODES {
            keeps_the_text_rules(words(ReasonKind::AccessCheck, &[], code), code);
        }
        assert_eq!(
            words(ReasonKind::AccessCheck, &[], "something_else"),
            words(ReasonKind::AccessCheck, &[], "")
        );
        assert_eq!(
            words(ReasonKind::AccessCheck, &[], "not_granted").line,
            "This agent may not use this credential."
        );
        assert_eq!(
            words(ReasonKind::ForeignProject, &[], "").short,
            "Another project's credential"
        );
    }

    #[test]
    fn a_flagged_run_reads_its_first_flag_in_order() {
        let words = words(
            ReasonKind::HookFlags,
            &flags(&["injection_phrase", "secret_output"]),
            "",
        );
        assert_eq!(words.line, "The command could print the secret.");
        assert_eq!(words.short, "Could print the secret");
        assert_eq!(
            super::words(ReasonKind::HookFlags, &flags(&["injection_phrase"]), "").line,
            "The request text mentions the bouncer or an approval."
        );
        assert_eq!(
            super::words(
                ReasonKind::HookFlags,
                &flags(&["injection_phrase", "some_new_flag"]),
                ""
            )
            .line,
            "A safety rule flagged this run."
        );
        assert_eq!(
            super::words(ReasonKind::HookFlags, &[], "").line,
            "A safety rule flagged this run."
        );
        // The other kinds keep their own words whatever the flags.
        assert_eq!(
            super::words(
                ReasonKind::HookUnverified,
                &flags(&["hook_unverified", "secret_output"]),
                ""
            )
            .line,
            "Apassy could not confirm your prompt."
        );
    }

    #[test]
    fn the_flags_sentence_names_each_flag_and_how_long_it_asks() {
        assert_eq!(
            flags_sentence(&flags(&["injection_phrase", "secret_output"])),
            "The command could print the secret. The request text mentions the bouncer or an approval."
        );
        assert_eq!(
            flags_sentence(&flags(&["injection_phrase"])),
            "The request text mentions the bouncer or an approval."
        );
        assert_eq!(
            flags_sentence(&flags(&["hook_unverified"])),
            "Apassy could not confirm your prompt."
        );
        assert_eq!(
            flags_sentence(&flags(&["a_new_one", "another_new_one"])),
            "A safety rule flagged this run."
        );
        // How long a run asks is a sentence of its own, for the owner's window.
        assert_eq!(
            every_time(
                ReasonKind::HookFlags,
                &flags(&["injection_phrase", "secret_output"])
            ),
            Some("A command like this asks every time.")
        );
        assert_eq!(
            every_time(ReasonKind::HookFlags, &flags(&["injection_phrase"])),
            Some("Apassy asks while the text says this.")
        );
        assert_eq!(
            every_time(ReasonKind::HookUnverified, &flags(&["hook_unverified"])),
            Some("Apassy asks until it can confirm your prompt.")
        );
        for flag in every_flag() {
            assert!(every_time(ReasonKind::Other, &flags(&[flag.as_str()])).is_some());
        }
        for flag in every_flag() {
            assert!(
                !flags_sentence(&flags(&[flag.as_str()])).contains('_'),
                "{flag}"
            );
        }
        assert_eq!(every_time(ReasonKind::ForeignProject, &[]), None);
        assert_eq!(
            every_time(ReasonKind::MissingTask, &[]),
            Some("Apassy asks until the agent sends your task.")
        );
    }

    #[test]
    fn old_rows_get_a_kind_from_their_columns() {
        let none = DecisionWhy::default();
        assert_eq!(kind_of(&none, "model", &[]), ReasonKind::ModelAllowed);
        assert_eq!(
            kind_of(&none, "pattern", &[]),
            ReasonKind::RememberedPattern
        );
        assert_eq!(kind_of(&none, "answer", &[]), ReasonKind::RememberedAnswer);
        assert_eq!(kind_of(&none, "rule", &[]), ReasonKind::AccessCheck);
        assert_eq!(
            kind_of(&none, "owner", &flags(&["secret_output"])),
            ReasonKind::HookFlags
        );
        assert_eq!(
            kind_of(
                &none,
                "no_answer",
                &flags(&["hook_ambiguous", "hook_channel"])
            ),
            ReasonKind::HookAmbiguous
        );
        assert_eq!(kind_of(&none, "owner", &[]), ReasonKind::Other);
        let stored = DecisionWhy {
            reason: "ForeignProject".to_owned(),
            ..DecisionWhy::default()
        };
        assert_eq!(
            kind_of(&stored, "no_answer", &[]),
            ReasonKind::ForeignProject
        );
        let unknown = DecisionWhy {
            reason: "NoSuchKind".to_owned(),
            ..DecisionWhy::default()
        };
        assert_eq!(kind_of(&unknown, "model", &[]), ReasonKind::ModelAllowed);
    }
}
