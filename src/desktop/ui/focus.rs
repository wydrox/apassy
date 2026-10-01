//! Keyboard focus that follows the owner.
//!
//! egui moves the focus with Tab, Shift-Tab, and the arrow keys. It does not give the
//! focus back when a sheet closes, and a control that goes away after a press drops
//! the focus, so the next Tab starts again at the sidebar. This module:
//!
//! - knows if the last input came from the keyboard ([`kit::keyboard_mode`]),
//! - keeps the focus from before each sheet, and gives it back when the sheet closes,
//! - moves the focus to the first control of the page after a navigation, and when the
//!   focused control went away after a key press.
//!
//! It moves the focus only for a keyboard user. A pointer user sees no focus ring that
//! they did not ask for.

use eframe::egui::{self, Event, FocusDirection, Id, Key, LayerId};

use super::kit;

/// Frames to wait for a widget that should take the focus back.
const RETRIES: u8 = 3;

#[derive(Default)]
pub(crate) struct FocusState {
    /// The focused widget at the end of the last frame.
    last: Option<Id>,
    /// The top modal layer at the end of the last frame.
    top: Option<LayerId>,
    /// For each open modal layer, the focus from before it opened.
    stack: Vec<(LayerId, Option<Id>)>,
    /// A widget that takes the focus when it is there and not behind a sheet.
    restore: Option<(Id, u8)>,
    /// Move the focus to the first control of the page in the next frame.
    page_start: bool,
    /// Escape was pressed in this frame or the last one. Escape clears the focus on
    /// purpose, so the focus does not come back after it.
    escape: bool,
    /// Frames to draw after a key press, so that a focus change settles without
    /// waiting for the next event.
    settle: u8,
}

impl FocusState {
    /// After a navigation, the first control of the new page takes the focus (for a
    /// keyboard user).
    #[cfg_attr(not(feature = "vault"), allow(dead_code))]
    pub(crate) fn focus_page_start(&mut self) {
        self.page_start = true;
    }
}

/// At the start of a frame: note if the input comes from the keyboard.
pub(crate) fn begin_frame(state: &mut FocusState, ctx: &egui::Context) {
    let (keyboard, pointer, escape) = ctx.input(|input| {
        let mut keyboard = false;
        let mut pointer = false;
        let mut escape = false;
        for event in &input.events {
            match event {
                Event::Key {
                    key, pressed: true, ..
                } => {
                    keyboard = true;
                    escape |= *key == Key::Escape;
                }
                Event::PointerButton { pressed: true, .. } => pointer = true,
                _ => {}
            }
        }
        (keyboard, pointer, escape)
    });
    if pointer {
        kit::set_keyboard_mode(ctx, false);
    } else if keyboard {
        kit::set_keyboard_mode(ctx, true);
        state.settle = 3;
    }
    state.escape = escape || (state.escape && !keyboard && !pointer);
}

/// Move the focus to the first control that registers after this call, when the page
/// asked for it. Call it just before the page draws.
pub(crate) fn page_start(state: &mut FocusState, ctx: &egui::Context) {
    if !std::mem::take(&mut state.page_start) || !kit::keyboard_mode(ctx) {
        return;
    }
    if ctx.memory(|memory| memory.top_modal_layer()).is_some() {
        return;
    }
    ctx.memory_mut(|memory| {
        if let Some(focused) = memory.focused() {
            memory.surrender_focus(focused);
        }
        memory.move_focus(FocusDirection::Next);
    });
}

/// At the end of a frame: keep the focus for each sheet that opens, give it back when
/// the sheet closes, and catch a focus that went away.
pub(crate) fn end_frame(state: &mut FocusState, ctx: &egui::Context) {
    let keyboard = kit::keyboard_mode(ctx);
    let top = ctx.memory(|memory| memory.top_modal_layer());
    let focused = ctx.memory(|memory| memory.focused());

    let changed = top != state.top;
    if changed {
        match top {
            None => {
                // Every sheet closed. The focus from before the first one comes back.
                if let Some((_, before)) = state.stack.drain(..).next() {
                    state.restore = before.map(|id| (id, RETRIES));
                }
            }
            Some(layer) => {
                if let Some(index) = state.stack.iter().position(|(open, _)| *open == layer) {
                    // A sheet over this one closed: the focus inside this one comes back.
                    let above = state.stack.split_off(index + 1);
                    if let Some((_, before)) = above.into_iter().next() {
                        state.restore = before.map(|id| (id, RETRIES));
                    }
                } else {
                    // A new sheet. Keep the focus of the frame before it opened.
                    state.stack.push((layer, state.last));
                    state.restore = None;
                }
            }
        }
        state.top = top;
    }

    if let Some((id, tries)) = state.restore.take() {
        // The focus can still name a control of the closed sheet for a frame, so the
        // restore does not wait for an empty focus.
        if keyboard && focused != Some(id) {
            let ready = ctx
                .read_response(id)
                .is_some_and(|response| ctx.memory(|m| m.allows_interaction(response.layer_id)));
            if ready {
                ctx.memory_mut(|memory| memory.request_focus(id));
                ctx.request_repaint();
            } else if tries > 0 {
                state.restore = Some((id, tries - 1));
                ctx.request_repaint();
            } else if top.is_none() {
                state.page_start = true;
                ctx.request_repaint();
            }
        }
    } else if keyboard
        && focused.is_none()
        && state.last.is_some()
        && !changed
        && top.is_none()
        && !state.escape
    {
        // The focused control went away after a key press, for example "Mark as seen".
        // Without this, the next Tab starts again at the sidebar.
        state.page_start = true;
        ctx.request_repaint();
    }
    state.last = ctx.memory(|memory| memory.focused());
    if state.settle > 0 {
        state.settle -= 1;
        ctx.request_repaint();
    }
}
