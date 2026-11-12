//! The frame of the tunnel mux and the stream rules (docs/contracts/connect-tunnel-v1.md
//! section 4).
//!
//! ```text
//! [stream u32 BE][kind u8][flags u8][len u16 BE][payload: len bytes]
//! ```
//!
//! One frame is one WebSocket binary message. [`decode`] runs the checks of section 4 in
//! the contract's order and names the first failure; [`Sequencer`] keeps the state of
//! each stream of one node WebSocket and names the first broken stream rule. Both are
//! pure: no IO, no clock, no allocation beyond the payload and one entry per live stream.
//!
//! Each direction of a stream has a window: the payload bytes that its sender may still
//! send. It starts at [`INITIAL_WINDOW`], data spends it, and a `window` frame of the
//! receiver adds to it as the receiver's consumer drains the stream ([`Sequencer::credit`]).
//! Data over the window is the stream rule `over_window`.

use std::collections::HashMap;

/// The header bytes before the payload.
pub const HEADER_LEN: usize = 8;
/// The largest payload of one frame.
pub const MAX_PAYLOAD: usize = 16384;
/// The largest WebSocket message that can hold a frame.
pub const MAX_MESSAGE: usize = HEADER_LEN + MAX_PAYLOAD;

/// Flag bit 0: the first frame of a stream, from Connect only.
pub const OPEN: u8 = 0x01;
/// Flag bit 1: the sender sends no more bytes on this stream.
pub const CLOSE: u8 = 0x02;
/// Flag bit 2: the stream ends now, in both directions.
pub const RESET: u8 = 0x04;
/// Flag bit 3: the receiver of a direction lets its sender send more: the payload is 4
/// bytes, the added window (u32 BE, at least 1).
pub const WINDOW: u8 = 0x08;
const KNOWN_FLAGS: u8 = OPEN | CLOSE | RESET | WINDOW;
/// The payload length of a `window` frame.
pub const WINDOW_LEN: usize = 4;
/// The window of each direction of a new stream, before any `window` frame: the bytes
/// of payload (the `open`'s own included) that its sender may send.
pub const INITIAL_WINDOW: u64 = 64 * 1024;
/// The largest window that a direction holds; more is the stream rule `over_window`.
pub const MAX_WINDOW: u64 = 16 * 1024 * 1024;

/// What a stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A dial of a device (pinned TLS inside).
    Device = 1,
    /// TLS of a cloud agent through the SNI ingress (port 443).
    Public = 2,
    /// One plain ACME HTTP-01 request through the ingress (port 80).
    Acme = 3,
}

impl Kind {
    pub fn from_byte(byte: u8) -> Option<Kind> {
        match byte {
            1 => Some(Kind::Device),
            2 => Some(Kind::Public),
            3 => Some(Kind::Acme),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Device => "device",
            Kind::Public => "public",
            Kind::Acme => "acme",
        }
    }
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub stream: u32,
    pub kind: Kind,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn is_open(&self) -> bool {
        self.flags & OPEN != 0
    }
    pub fn is_close(&self) -> bool {
        self.flags & CLOSE != 0
    }
    pub fn is_reset(&self) -> bool {
        self.flags & RESET != 0
    }
    pub fn is_window(&self) -> bool {
        self.flags & WINDOW != 0
    }

    /// The window that a `window` frame adds (0 for any other frame).
    pub fn window_added(&self) -> u32 {
        window_of(self.flags, &self.payload)
    }

    /// The bytes of this frame. Panics never: a payload over [`MAX_PAYLOAD`] is a bug of
    /// the caller, and [`encode`] cuts nothing; callers split before.
    pub fn encode(&self) -> Vec<u8> {
        encode(self.stream, self.kind, self.flags, &self.payload)
    }
}

/// The bytes of one frame. `payload` must be at most [`MAX_PAYLOAD`] bytes (the callers
/// split), and the length field is its length.
pub fn encode(stream: u32, kind: Kind, flags: u8, payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_PAYLOAD);
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&stream.to_be_bytes());
    out.push(kind as u8);
    out.push(flags);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The bytes of a `window` frame that adds `added` bytes to the window of the other side.
pub fn window(stream: u32, kind: Kind, added: u32) -> Vec<u8> {
    encode(stream, kind, WINDOW, &added.to_be_bytes())
}

fn window_of(flags: u8, payload: &[u8]) -> u32 {
    match <[u8; WINDOW_LEN]>::try_from(payload) {
        Ok(bytes) if flags & WINDOW != 0 => u32::from_be_bytes(bytes),
        _ => 0,
    }
}

/// Why a message is not a frame. A receiver closes the WebSocket with 1002.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    ShortHeader,
    LengthMismatch,
    PayloadTooLarge,
    ReservedStream,
    UnknownKind,
    UnknownFlags,
    BadReset,
    BadWindow,
    EmptyFrame,
}

impl FrameError {
    /// The code of the contract (`frames.json` `reason`).
    pub fn code(self) -> &'static str {
        match self {
            FrameError::ShortHeader => "short_header",
            FrameError::LengthMismatch => "length_mismatch",
            FrameError::PayloadTooLarge => "payload_too_large",
            FrameError::ReservedStream => "reserved_stream",
            FrameError::UnknownKind => "unknown_kind",
            FrameError::UnknownFlags => "unknown_flags",
            FrameError::BadReset => "bad_reset",
            FrameError::BadWindow => "bad_window",
            FrameError::EmptyFrame => "empty_frame",
        }
    }
}

/// Decodes one WebSocket binary message as a frame, with the checks of section 4 in
/// their order.
pub fn decode(message: &[u8]) -> Result<Frame, FrameError> {
    if message.len() < HEADER_LEN {
        return Err(FrameError::ShortHeader);
    }
    let stream = u32::from_be_bytes([message[0], message[1], message[2], message[3]]);
    let kind = message[4];
    let flags = message[5];
    let len = usize::from(u16::from_be_bytes([message[6], message[7]]));
    if message.len() != HEADER_LEN + len {
        return Err(FrameError::LengthMismatch);
    }
    if len > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge);
    }
    if stream == 0 {
        return Err(FrameError::ReservedStream);
    }
    let Some(kind) = Kind::from_byte(kind) else {
        return Err(FrameError::UnknownKind);
    };
    if flags & !KNOWN_FLAGS != 0 {
        return Err(FrameError::UnknownFlags);
    }
    if flags & RESET != 0 && (flags != RESET || len != 0) {
        return Err(FrameError::BadReset);
    }
    if flags & WINDOW != 0
        && (flags != WINDOW || len != WINDOW_LEN || message[HEADER_LEN..] == [0; WINDOW_LEN])
    {
        return Err(FrameError::BadWindow);
    }
    if flags == 0 && len == 0 {
        return Err(FrameError::EmptyFrame);
    }
    Ok(Frame {
        stream,
        kind,
        flags,
        payload: message[HEADER_LEN..].to_vec(),
    })
}

/// The direction of a frame on a node WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Connect to the node.
    ToNode,
    /// The node to Connect.
    ToConnect,
}

/// A broken stream rule. The side that saw it resets that stream; the WebSocket stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    NotOpen,
    OpenByNode,
    AlreadyOpen,
    Reused,
    KindMismatch,
    Closed,
    OverWindow,
}

impl StreamError {
    /// The code of the contract (`frames.json` sequence `error`).
    pub fn code(self) -> &'static str {
        match self {
            StreamError::NotOpen => "not_open",
            StreamError::OpenByNode => "open_by_node",
            StreamError::AlreadyOpen => "already_open",
            StreamError::Reused => "reused",
            StreamError::KindMismatch => "kind_mismatch",
            StreamError::Closed => "closed",
            StreamError::OverWindow => "over_window",
        }
    }
}

/// What a frame did to its stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied<T> {
    /// A new stream; `T` is the value given for it.
    Opened(T),
    /// A frame of a live stream; `ended` when the stream ended with it (both directions
    /// closed, or a reset). An ended stream is gone from the sequencer.
    Frame { value: T, ended: bool },
    /// A frame for a stream that ended earlier: dropped without an error.
    Dropped,
}

#[derive(Debug)]
struct StreamState<T> {
    kind: Kind,
    to_node_closed: bool,
    to_connect_closed: bool,
    /// The window of each direction: payload bytes its sender may still send.
    to_node_window: u64,
    to_connect_window: u64,
    value: T,
}

impl<T> StreamState<T> {
    fn window_mut(&mut self, dir: Dir) -> &mut u64 {
        match dir {
            Dir::ToNode => &mut self.to_node_window,
            Dir::ToConnect => &mut self.to_connect_window,
        }
    }
}

impl Dir {
    /// The other direction.
    pub fn back(self) -> Dir {
        match self {
            Dir::ToNode => Dir::ToConnect,
            Dir::ToConnect => Dir::ToNode,
        }
    }
}

/// The state of the streams of one node WebSocket. Holds one entry for each live stream
/// and the highest id opened; ended streams leave no state.
#[derive(Debug)]
pub struct Sequencer<T> {
    streams: HashMap<u32, StreamState<T>>,
    last_opened: u32,
}

impl<T> Default for Sequencer<T> {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
            last_opened: 0,
        }
    }
}

impl<T: Clone> Sequencer<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest stream id opened on this WebSocket (0 before the first).
    pub fn last_opened(&self) -> u32 {
        self.last_opened
    }

    /// The number of live streams.
    pub fn live(&self) -> usize {
        self.streams.len()
    }

    /// The value of a live stream.
    pub fn get(&self, stream: u32) -> Option<&T> {
        self.streams.get(&stream).map(|state| &state.value)
    }

    /// The live streams and their values.
    pub fn values(&self) -> impl Iterator<Item = (u32, &T)> {
        self.streams.iter().map(|(id, state)| (*id, &state.value))
    }

    /// Whether the given direction of a live stream is closed.
    pub fn is_closed(&self, stream: u32, dir: Dir) -> bool {
        match self.streams.get(&stream) {
            Some(state) => match dir {
                Dir::ToNode => state.to_node_closed,
                Dir::ToConnect => state.to_connect_closed,
            },
            None => true,
        }
    }

    /// The window of a direction of a live stream: the payload bytes that its sender may
    /// still send. `None`: the stream is not live.
    pub fn credit(&self, stream: u32, dir: Dir) -> Option<u64> {
        self.streams.get(&stream).map(|state| match dir {
            Dir::ToNode => state.to_node_window,
            Dir::ToConnect => state.to_connect_window,
        })
    }

    /// Applies one valid frame (after [`decode`]) in direction `dir`. `make` gives the
    /// value of a stream that this frame opens.
    pub fn apply(
        &mut self,
        dir: Dir,
        frame: &Frame,
        make: impl FnOnce() -> T,
    ) -> Result<Applied<T>, StreamError> {
        self.apply_parts(
            dir,
            frame.stream,
            frame.kind,
            frame.flags,
            &frame.payload,
            make,
        )
    }

    /// [`Sequencer::apply`] of a frame without a payload (an `open`, a `close`, a
    /// `reset`).
    pub fn apply_head(
        &mut self,
        dir: Dir,
        stream: u32,
        kind: Kind,
        flags: u8,
        make: impl FnOnce() -> T,
    ) -> Result<Applied<T>, StreamError> {
        self.apply_parts(dir, stream, kind, flags, &[], make)
    }

    /// [`Sequencer::apply`] on the fields of a frame. The payload of data spends the
    /// window of `dir`; a `window` frame adds to the window of the other direction (the
    /// one that its sender receives), also after the sender's own direction closed.
    pub fn apply_parts(
        &mut self,
        dir: Dir,
        stream: u32,
        kind: Kind,
        flags: u8,
        payload: &[u8],
        make: impl FnOnce() -> T,
    ) -> Result<Applied<T>, StreamError> {
        let len = payload.len() as u64;
        if flags & OPEN != 0 {
            if dir == Dir::ToConnect {
                return Err(StreamError::OpenByNode);
            }
            if self.streams.contains_key(&stream) {
                return Err(StreamError::AlreadyOpen);
            }
            if stream <= self.last_opened {
                return Err(StreamError::Reused);
            }
            if len > INITIAL_WINDOW {
                return Err(StreamError::OverWindow);
            }
            let value = make();
            self.last_opened = stream;
            self.streams.insert(
                stream,
                StreamState {
                    kind,
                    to_node_closed: flags & CLOSE != 0,
                    to_connect_closed: false,
                    to_node_window: INITIAL_WINDOW - len,
                    to_connect_window: INITIAL_WINDOW,
                    value: value.clone(),
                },
            );
            return Ok(Applied::Opened(value));
        }
        if stream > self.last_opened {
            return Err(StreamError::NotOpen);
        }
        let Some(state) = self.streams.get_mut(&stream) else {
            return Ok(Applied::Dropped);
        };
        if state.kind != kind {
            return Err(StreamError::KindMismatch);
        }
        if flags & RESET != 0 {
            let state = self.streams.remove(&stream).expect("present");
            return Ok(Applied::Frame {
                value: state.value,
                ended: true,
            });
        }
        if flags & WINDOW != 0 {
            let window = state.window_mut(dir.back());
            let added = u64::from(window_of(flags, payload));
            if *window + added > MAX_WINDOW {
                return Err(StreamError::OverWindow);
            }
            *window += added;
            return Ok(Applied::Frame {
                value: state.value.clone(),
                ended: false,
            });
        }
        let closed = match dir {
            Dir::ToNode => &mut state.to_node_closed,
            Dir::ToConnect => &mut state.to_connect_closed,
        };
        if *closed {
            return Err(StreamError::Closed);
        }
        let close = flags & CLOSE != 0;
        let window = state.window_mut(dir);
        if len > *window {
            return Err(StreamError::OverWindow);
        }
        *window -= len;
        if close {
            match dir {
                Dir::ToNode => state.to_node_closed = true,
                Dir::ToConnect => state.to_connect_closed = true,
            }
        }
        if state.to_node_closed && state.to_connect_closed {
            let state = self.streams.remove(&stream).expect("present");
            return Ok(Applied::Frame {
                value: state.value,
                ended: true,
            });
        }
        Ok(Applied::Frame {
            value: state.value.clone(),
            ended: false,
        })
    }

    /// Ends a live stream (a reset that this side decides). Returns its value.
    pub fn remove(&mut self, stream: u32) -> Option<T> {
        self.streams.remove(&stream).map(|state| state.value)
    }

    /// Ends every live stream. Returns their values.
    pub fn drain(&mut self) -> Vec<(u32, T)> {
        self.streams
            .drain()
            .map(|(id, state)| (id, state.value))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_checks() {
        let bytes = encode(7, Kind::Device, OPEN, b"abc");
        let frame = decode(&bytes).unwrap();
        assert_eq!(frame.stream, 7);
        assert_eq!(frame.encode(), bytes);
        assert_eq!(decode(&bytes[..7]), Err(FrameError::ShortHeader));
        assert_eq!(
            decode(&encode(1, Kind::Device, RESET | CLOSE, b"")),
            Err(FrameError::BadReset)
        );
    }

    #[test]
    fn ended_streams_drop_late_frames() {
        let mut seq: Sequencer<()> = Sequencer::new();
        seq.apply_head(Dir::ToNode, 3, Kind::Device, OPEN, || ())
            .unwrap();
        assert_eq!(
            seq.apply_head(Dir::ToConnect, 3, Kind::Device, RESET, || ()),
            Ok(Applied::Frame {
                value: (),
                ended: true
            })
        );
        assert_eq!(
            seq.apply_head(Dir::ToConnect, 3, Kind::Device, 0, || ()),
            Ok(Applied::Dropped)
        );
        assert_eq!(seq.live(), 0);
    }

    #[test]
    fn data_spends_the_window_and_a_window_frame_adds_to_the_other_direction() {
        let mut seq: Sequencer<()> = Sequencer::new();
        let first = vec![0u8; 1000];
        seq.apply_parts(Dir::ToNode, 1, Kind::Device, OPEN, &first, || ())
            .unwrap();
        assert_eq!(seq.credit(1, Dir::ToNode), Some(INITIAL_WINDOW - 1000));
        assert_eq!(seq.credit(1, Dir::ToConnect), Some(INITIAL_WINDOW));
        let rest = vec![0u8; (INITIAL_WINDOW - 1000) as usize];
        for piece in rest.chunks(MAX_PAYLOAD) {
            seq.apply_parts(Dir::ToNode, 1, Kind::Device, 0, piece, || ())
                .unwrap();
        }
        assert_eq!(seq.credit(1, Dir::ToNode), Some(0));
        assert_eq!(
            seq.apply_parts(Dir::ToNode, 1, Kind::Device, 0, b"x", || ()),
            Err(StreamError::OverWindow)
        );
        // The node closes its side and still lets Connect send more.
        seq.apply_head(Dir::ToConnect, 1, Kind::Device, CLOSE, || ())
            .unwrap();
        let grant = decode(&window(1, Kind::Device, 10)).unwrap();
        assert_eq!(grant.window_added(), 10);
        seq.apply(Dir::ToConnect, &grant, || ()).unwrap();
        assert_eq!(seq.credit(1, Dir::ToNode), Some(10));
        seq.apply_parts(Dir::ToNode, 1, Kind::Device, 0, &[1; 10], || ())
            .unwrap();
        // More than the largest window is a broken rule too.
        let huge = decode(&window(1, Kind::Device, u32::MAX)).unwrap();
        assert_eq!(
            seq.apply(Dir::ToConnect, &huge, || ()),
            Err(StreamError::OverWindow)
        );
        assert_eq!(
            decode(&encode(1, Kind::Device, WINDOW, &[0, 0, 0, 0])),
            Err(FrameError::BadWindow)
        );
        assert_eq!(
            decode(&encode(1, Kind::Device, WINDOW | CLOSE, &[0, 0, 0, 1])),
            Err(FrameError::BadWindow)
        );
        assert_eq!(
            decode(&encode(1, Kind::Device, WINDOW, &[0, 0, 1])),
            Err(FrameError::BadWindow)
        );
    }
}
