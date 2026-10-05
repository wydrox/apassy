//! Native file panels only choose a path. Reading, importing, writing, and locking
//! remain explicit actions of the form that owns the path.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use eframe::egui;

use super::kit::{self, Style};

type Selection = Pin<Box<dyn Future<Output = Option<PathBuf>> + Send>>;

#[derive(Clone, Copy)]
pub(crate) enum DialogKind {
    ImportExport,
    OpenBackup,
    SaveBackup,
    OpenVault,
    OpenSyncedVault,
    SaveVault,
}

struct Pending {
    field: &'static str,
    original: String,
    selection: Selection,
}

/// At most one native panel can be open from a form. Discard its result when the
/// form closes, so a later result cannot change a new form or another vault.
#[derive(Default)]
pub(crate) struct FilePickerState {
    pending: Option<Pending>,
}

impl FilePickerState {
    pub(crate) fn forget(&mut self) {
        self.pending = None;
    }

    fn poll(&mut self, ctx: &egui::Context, field: &str, value: &mut String) -> bool {
        let Some(pending) = &mut self.pending else {
            return false;
        };
        if pending.field != field {
            return false;
        }
        let waker = Waker::from(Arc::new(Repaint(ctx.clone())));
        let mut task = Context::from_waker(&waker);
        if let Poll::Ready(selected) = pending.selection.as_mut().poll(&mut task) {
            let mut changed = false;
            // Do not overwrite a manual change made while the panel was open.
            if *value == pending.original
                && let Some(path) = selected
            {
                let path = path.display().to_string();
                changed = *value != path;
                *value = path;
            }
            self.pending = None;
            return changed;
        }
        false
    }

    fn start(&mut self, ctx: &egui::Context, field: &'static str, value: &str, kind: DialogKind) {
        if self.pending.is_some() {
            return;
        }
        let original = value.to_owned();
        let value = original.clone();
        let directory = directory_hint(ctx, &value);
        let selection: Selection = Box::pin(async move {
            let dialog = dialog(kind, &value, directory.await);
            match kind {
                DialogKind::SaveBackup | DialogKind::SaveVault => dialog.save_file().await,
                _ => dialog.pick_file().await,
            }
            .map(|file| file.path().to_path_buf())
        });
        self.pending = Some(Pending {
            field,
            original,
            selection,
        });
        // The first poll starts the future. Its waker requests the next frame when
        // the native panel completes; no executor or blocking wait is needed.
        ctx.request_repaint();
    }
}

struct Repaint(egui::Context);

impl Wake for Repaint {
    fn wake(self: Arc<Self>) {
        self.0.request_repaint();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.request_repaint();
    }
}

const DIRECTORY_HINT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct DirectoryWorker {
    handle: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct DirectoryResult {
    result: Option<Option<PathBuf>>,
    waker: Option<Waker>,
}

struct DirectoryHint {
    result: Arc<Mutex<DirectoryResult>>,
    deadline: Instant,
    ctx: egui::Context,
}

impl DirectoryWorker {
    fn start(
        &self,
        ctx: &egui::Context,
        timeout: Duration,
        operation: impl FnOnce() -> Option<PathBuf> + Send + 'static,
    ) -> DirectoryHint {
        let result = Arc::new(Mutex::new(DirectoryResult::default()));
        let hint = DirectoryHint {
            result: Arc::clone(&result),
            deadline: Instant::now() + timeout,
            ctx: ctx.clone(),
        };
        let mut slot = self.handle.lock().unwrap_or_else(PoisonError::into_inner);
        // A blocked File Provider call cannot be canceled. Keep its slot after
        // a timeout, so more panels cannot create more blocked threads.
        if slot.as_ref().is_some_and(|handle| !handle.is_finished()) {
            result.lock().unwrap_or_else(PoisonError::into_inner).result = Some(None);
            return hint;
        }
        if let Some(finished) = slot.take() {
            let _ = finished.join();
        }
        let completion = Arc::clone(&result);
        match thread::Builder::new()
            .name("apassy-file-panel-directory".to_owned())
            .spawn(move || {
                let directory = operation();
                let waker = {
                    let mut result = completion.lock().unwrap_or_else(PoisonError::into_inner);
                    result.result = Some(directory);
                    result.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
            }) {
            Ok(handle) => *slot = Some(handle),
            Err(_) => {
                result.lock().unwrap_or_else(PoisonError::into_inner).result = Some(None);
            }
        }
        hint
    }
}

impl Future for DirectoryHint {
    type Output = Option<PathBuf>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let mut result = self.result.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(directory) = result.result.take() {
            return Poll::Ready(directory);
        }
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            result.waker = None;
            return Poll::Ready(None);
        }
        result.waker = Some(task.waker().clone());
        self.ctx.request_repaint_after(remaining);
        Poll::Pending
    }
}

/// Directory metadata can block in File Provider folders. Check it off the
/// event thread, then open the panel without a directory hint after a timeout.
fn directory_hint(ctx: &egui::Context, value: &str) -> DirectoryHint {
    static WORKER: OnceLock<DirectoryWorker> = OnceLock::new();
    let path = expand_home(value.trim());
    WORKER
        .get_or_init(DirectoryWorker::default)
        .start(ctx, DIRECTORY_HINT_TIMEOUT, move || {
            existing_directory(&path)
        })
}

fn existing_directory(path: &Path) -> Option<PathBuf> {
    if path.is_dir() {
        Some(path.to_owned())
    } else {
        path.parent()
            .filter(|parent| parent.is_dir())
            .map(Path::to_owned)
    }
}

fn dialog(kind: DialogKind, value: &str, directory: Option<PathBuf>) -> rfd::AsyncFileDialog {
    let mut dialog = rfd::AsyncFileDialog::new();
    dialog = match kind {
        DialogKind::ImportExport => dialog
            .set_title("Select a 1Password export")
            .add_filter("1Password export", &["1pux", "csv"]),
        DialogKind::OpenBackup => dialog.set_title("Select a vault backup"),
        DialogKind::SaveBackup => dialog
            .set_title("Save the vault backup")
            .set_file_name("apassy.backup"),
        DialogKind::OpenVault => dialog.set_title("Select a vault file"),
        DialogKind::OpenSyncedVault => dialog
            .set_title("Select a synced vault file")
            .add_filter("Apassy synced vault", &["apassy"]),
        DialogKind::SaveVault => dialog
            .set_title("Select the new vault file")
            .set_file_name("apassy.db"),
    };
    // The vault store accepts any filename, so backup/vault panels have no
    // extension filter, except for synced vaults, which use `.apassy`. This also
    // permits existing local vault and backup files with custom names.
    let path = expand_home(value.trim());
    let is_directory = directory.as_deref() == Some(path.as_path());
    if let Some(directory) = directory {
        dialog = dialog.set_directory(directory);
    }
    if !is_directory
        && !value.trim().is_empty()
        && matches!(kind, DialogKind::SaveBackup | DialogKind::SaveVault)
        && let Some(name) = path.file_name()
    {
        dialog = dialog.set_file_name(name.to_string_lossy());
    }
    dialog
}

fn expand_home(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        Path::new(&home).join(rest)
    } else {
        PathBuf::from(value)
    }
}

/// A native file panel without a path field. Selection does not read or open the file.
pub(crate) fn choose_file(
    ui: &mut egui::Ui,
    state: &mut FilePickerState,
    value: &mut String,
    field: &'static str,
    label: &str,
    kind: DialogKind,
) -> egui::Response {
    let selected = state.poll(ui.ctx(), field, value);
    let mut response = ui
        .add_enabled_ui(state.pending.is_none(), |ui| {
            kit::small_button(ui, label, Style::Bordered)
        })
        .inner;
    if response.clicked() {
        state.start(ui.ctx(), field, value, kind);
    }
    if selected {
        response.mark_changed();
    }
    response
}

/// A manual path field with a native Browse button. Return the text field response
/// so the caller can keep its existing Return-key action.
pub(crate) fn path_input(
    ui: &mut egui::Ui,
    state: &mut FilePickerState,
    value: &mut String,
    field: &'static str,
    placeholder: &str,
    kind: DialogKind,
) -> egui::Response {
    let selected = state.poll(ui.ctx(), field, value);
    let mut response = ui
        .horizontal(|ui| {
            let width = (ui.available_width() - 92.0).max(80.0);
            let input = ui
                .allocate_ui_with_layout(
                    egui::vec2(width, 28.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| kit::text_input(ui, value, field, placeholder),
                )
                .inner;
            if ui
                .add_enabled_ui(state.pending.is_none(), |ui| {
                    kit::small_button(ui, "Browse…", Style::Bordered)
                })
                .inner
                .clicked()
            {
                state.start(ui.ctx(), field, value, kind);
            }
            input
        })
        .inner;
    if selected {
        response.mark_changed();
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    fn poll_hint(hint: &mut DirectoryHint) -> Poll<Option<PathBuf>> {
        let waker = Waker::from(Arc::new(Repaint(hint.ctx.clone())));
        Pin::new(hint).poll(&mut Context::from_waker(&waker))
    }

    #[test]
    fn directory_hint_checks_run_off_the_event_thread_and_keep_directory_choices() {
        let root = tempfile::tempdir().expect("directory");
        let event_thread = thread::current().id();
        let worker = DirectoryWorker::default();
        for path in [root.path().to_owned(), root.path().join("new.backup")] {
            let mut hint = worker.start(
                &egui::Context::default(),
                Duration::from_secs(1),
                move || {
                    assert_ne!(thread::current().id(), event_thread);
                    existing_directory(&path)
                },
            );
            let limit = Instant::now() + Duration::from_secs(1);
            loop {
                if let Poll::Ready(directory) = poll_hint(&mut hint) {
                    assert_eq!(directory.as_deref(), Some(root.path()));
                    break;
                }
                assert!(Instant::now() < limit, "directory hint did not finish");
                thread::yield_now();
            }
            // Completion wakes the future before the thread exits. Wait for the
            // test worker to end before checking the next successful operation.
            while worker
                .handle
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|handle| !handle.is_finished())
            {
                assert!(Instant::now() < limit, "directory worker did not end");
                thread::yield_now();
            }
        }
    }

    #[test]
    fn blocked_directory_hint_times_out_and_more_panels_do_not_add_workers() {
        let worker = DirectoryWorker::default();
        let ctx = egui::Context::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::clone(&calls);
        let (started, wait_started) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let before = Instant::now();
        let mut first = worker.start(&ctx, Duration::from_secs(2), move || {
            first_calls.fetch_add(1, Ordering::SeqCst);
            started.send(()).expect("started");
            blocked.recv().expect("release metadata check");
            Some(PathBuf::from("late directory"))
        });
        assert!(before.elapsed() < Duration::from_secs(1));
        wait_started
            .recv_timeout(Duration::from_secs(1))
            .expect("worker started");
        assert!(poll_hint(&mut first).is_pending());
        first.deadline = Instant::now();
        assert_eq!(poll_hint(&mut first), Poll::Ready(None));
        for _ in 0..3 {
            let next_calls = Arc::clone(&calls);
            let mut retry = worker.start(&ctx, Duration::from_secs(2), move || {
                next_calls.fetch_add(1, Ordering::SeqCst);
                Some(PathBuf::from("new directory"))
            });
            assert_eq!(poll_hint(&mut retry), Poll::Ready(None));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // A late directory hint is isolated from the panel that opened without
        // it. Dropping the future does not wait for its blocked worker.
        drop(first);
        release.send(()).expect("release worker");
        if let Some(handle) = worker.handle.lock().unwrap().take() {
            handle.join().expect("metadata worker");
        }
    }

    fn ready(field: &'static str, original: &str, result: Option<PathBuf>) -> FilePickerState {
        FilePickerState {
            pending: Some(Pending {
                field,
                original: original.to_owned(),
                selection: Box::pin(std::future::ready(result)),
            }),
        }
    }

    #[test]
    fn cancel_keeps_the_manual_path() {
        let mut state = ready("backup", "manual.backup", None);
        let mut value = "manual.backup".to_owned();
        assert!(!state.poll(&egui::Context::default(), "backup", &mut value));
        assert_eq!(value, "manual.backup");
        assert!(state.pending.is_none());
    }

    #[test]
    fn selected_backup_path_does_not_write_a_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("selected.backup");
        let mut state = ready("backup", "", Some(path.clone()));
        let mut value = String::new();
        assert!(state.poll(&egui::Context::default(), "backup", &mut value));
        assert_eq!(value, path.display().to_string());
        assert!(!path.exists(), "a panel result must not write a backup");
    }

    #[test]
    fn chooser_button_reports_selection_and_cancel_keeps_the_path() {
        let ctx = egui::Context::default();
        let mut state = ready("sync-open-path", "old.apassy", Some("Team.apassy".into()));
        let mut value = "old.apassy".to_owned();
        let mut changed = false;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            changed |= choose_file(
                ui,
                &mut state,
                &mut value,
                "sync-open-path",
                "Choose another file…",
                DialogKind::OpenSyncedVault,
            )
            .changed();
        });
        output.textures_delta.clear();
        assert!(changed);
        assert_eq!(value, "Team.apassy");
        state = ready("sync-open-path", &value, None);
        changed = false;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            changed |= choose_file(
                ui,
                &mut state,
                &mut value,
                "sync-open-path",
                "Choose another file…",
                DialogKind::OpenSyncedVault,
            )
            .changed();
        });
        output.textures_delta.clear();
        assert!(!changed);
        assert_eq!(value, "Team.apassy");
    }

    #[test]
    fn synced_selection_marks_the_path_field_changed() {
        let ctx = egui::Context::default();
        let mut state = ready("sync-open-path", "old.apassy", Some("team.apassy".into()));
        let mut value = "old.apassy".to_owned();
        let mut changed = false;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            changed |= path_input(
                ui,
                &mut state,
                &mut value,
                "sync-open-path",
                "",
                DialogKind::OpenSyncedVault,
            )
            .changed();
        });
        output.textures_delta.clear();
        assert_eq!(value, "team.apassy");
        assert!(changed, "the caller must clear its previous picked entry");
    }

    #[test]
    fn late_result_cannot_change_another_field_or_a_manual_change() {
        let ctx = egui::Context::default();
        let mut state = ready("import", "original.csv", Some("selected.csv".into()));
        let mut other = "other.backup".to_owned();
        state.poll(&ctx, "backup", &mut other);
        assert_eq!(other, "other.backup");
        let mut edited = "manual.csv".to_owned();
        state.poll(&ctx, "import", &mut edited);
        assert_eq!(edited, "manual.csv");
        assert!(state.pending.is_none());
    }

    #[test]
    fn closed_form_discards_a_late_result() {
        let mut state = ready("import", "", Some("selected.csv".into()));
        state.forget();
        let mut value = String::new();
        state.poll(&egui::Context::default(), "import", &mut value);
        assert!(value.is_empty());
    }
}
