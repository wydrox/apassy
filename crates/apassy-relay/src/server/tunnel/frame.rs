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
const KNOWN_FLAGS: u8 = OPEN | CLOSE | RESET;

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
    value: T,
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

    /// Applies one valid frame (after [`decode`]) in direction `dir`. `make` gives the
    /// value of a stream that this frame opens.
    pub fn apply(
        &mut self,
        dir: Dir,
        frame: &Frame,
        make: impl FnOnce() -> T,
    ) -> Result<Applied<T>, StreamError> {
        self.apply_head(dir, frame.stream, frame.kind, frame.flags, make)
    }

    /// [`Sequencer::apply`] on the header fields only.
    pub fn apply_head(
        &mut self,
        dir: Dir,
        stream: u32,
        kind: Kind,
        flags: u8,
        make: impl FnOnce() -> T,
    ) -> Result<Applied<T>, StreamError> {
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
            let value = make();
            self.last_opened = stream;
            self.streams.insert(
                stream,
                StreamState {
                    kind,
                    to_node_closed: flags & CLOSE != 0,
                    to_connect_closed: false,
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
        let closed = match dir {
            Dir::ToNode => &mut state.to_node_closed,
            Dir::ToConnect => &mut state.to_connect_closed,
        };
        if *closed {
            return Err(StreamError::Closed);
        }
        if flags & CLOSE != 0 {
            *closed = true;
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
}
