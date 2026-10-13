//! Questions of the broker through the relay (ADR 0025 §3e, stage 5 plan section A,
//! contract `docs/contracts/relay-questions-v1.md`).
//!
//! A run that waits for the owner is a question. With "Send questions through the relay"
//! on (a relay membership with the purpose `questions`, `crate::relay::membership`), this
//! Mac also seals each question with the question key of the vault and posts it to the
//! relay, which routes it to the other devices of the vault. Their answers come back
//! sealed and signed with a key of the `trusted_device` table; the first valid one takes
//! effect through the approval queue, as an answer on the card does. The relay sees the
//! routing only: no command, no credential name, no value.
//!
//! - [`envelope`]: the card, the answer, and the settle; the AAD, ChaCha20-Poly1305, and
//!   the answer string.
//! - [`client`]: the relay endpoints of the contract (section 10), and the device links
//!   of a notifications-only team ("Add an iPhone…").
//! - [`answer`]: the answering device (section 13).
//! - [`device_link`]: the answer key of an iPhone in its device link, for the row that
//!   the confirming Mac writes.
//! - [`worker`]: the asker, a waiter of its own next to the sync waiter (section 12), and
//!   the lister of the questions of the other devices (section 13).
//!
//! The local card and the local-network companion (companion-v1, digest v1) stay as
//! they are.

pub mod answer;
pub mod client;
pub mod device_link;
pub mod envelope;
pub mod worker;

pub use answer::{
    AnswerError, OpenedQuestion, PreparedAnswer, Unreadable, answer_from_mac, local_action,
    open_question, open_settle, prepare_answer, remote_owner_action, seal_answer, send_answer,
};
pub use client::{
    AnswerList, AnswerReceipt, AnswerRecord, Posted, QuestionList, QuestionRecord, QuestionsClient,
    QuestionsError, TeamDevice,
};
pub use envelope::{AnswerBody, Card, Choice, RemoteEnvironment, Sealed, SettleBody};
pub use worker::{
    QUESTION_WAIT, QuestionsConfig, QuestionsView, QuestionsWorker, RemoteAnswered,
    RemoteAnswering, RemoteQuestion, RemoteRefused,
};
