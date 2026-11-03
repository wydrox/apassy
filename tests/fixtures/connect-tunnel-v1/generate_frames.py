"""Makes tests/fixtures/connect-tunnel-v1/frames.json (docs/contracts/connect-tunnel-v1.md
section 4 and 11). Deterministic, synthetic bytes.

    python3 -I tests/fixtures/connect-tunnel-v1/generate_frames.py

A frame is `[stream u32 BE][kind u8][flags u8][len u16 BE][payload]`, one frame per
WebSocket binary message.
"""

import json
import pathlib
import struct

DIR = pathlib.Path(__file__).resolve().parent
OPEN, CLOSE, RESET = 0x01, 0x02, 0x04
DEVICE, PUBLIC, ACME = 1, 2, 3
MAX_PAYLOAD = 16384


def frame(stream, kind, flags, payload=b"", length=None):
    n = len(payload) if length is None else length
    return struct.pack(">IBBH", stream, kind, flags, n) + payload


# A TLS ClientHello record start (synthetic, truncated): what an ingress forwards first.
HELLO = bytes.fromhex("160301003a0100003603035a5a5a5a")
ACME_GET = (
    b"GET /.well-known/acme-challenge/SynthToken_0123 HTTP/1.1\r\n"
    b"Host: k7m2q4x3ca.node.example.test\r\n\r\n"
)

VALID = [
    ("device_open", 1, DEVICE, OPEN, b""),
    ("device_data", 1, DEVICE, 0, bytes.fromhex("1703030005") + b"hello"),
    ("device_close", 1, DEVICE, CLOSE, b""),
    ("public_open_with_client_hello", 2, PUBLIC, OPEN, HELLO),
    ("public_data_and_close", 2, PUBLIC, CLOSE, b"bye"),
    ("acme_open_with_request", 3, ACME, OPEN | CLOSE, ACME_GET),
    ("reset", 4, DEVICE, RESET, b""),
    ("max_stream_id", 0xFFFFFFFF, DEVICE, OPEN, b""),
    ("max_payload", 5, DEVICE, 0, b"\xab" * MAX_PAYLOAD),
]

INVALID = [
    ("short_header", frame(1, DEVICE, 0, b"x")[:7], "short_header"),
    ("length_longer_than_message", frame(1, DEVICE, 0, b"abc", length=4), "length_mismatch"),
    ("length_shorter_than_message", frame(1, DEVICE, 0, b"abc", length=2), "length_mismatch"),
    ("reserved_stream", frame(0, DEVICE, OPEN), "reserved_stream"),
    ("kind_zero", frame(1, 0, OPEN), "unknown_kind"),
    ("kind_four", frame(1, 4, OPEN), "unknown_kind"),
    ("unknown_flag", frame(1, DEVICE, 0x08, b"x"), "unknown_flags"),
    ("reset_with_payload", frame(1, DEVICE, RESET, b"x"), "bad_reset"),
    ("reset_with_open", frame(1, DEVICE, RESET | OPEN), "bad_reset"),
    ("empty_frame", frame(1, DEVICE, 0), "empty_frame"),
    ("payload_over_max", frame(1, DEVICE, 0, b"\x00" * (MAX_PAYLOAD + 1)), "payload_too_large"),
]

# Ordered frames on one node WebSocket, both directions, with the first error.
SEQUENCES = [
    {
        "name": "a_device_stream_opens_carries_data_and_closes_both_ways",
        "frames": [
            ["to_node", frame(7, DEVICE, OPEN, b"\x16\x03\x01").hex()],
            ["to_connect", frame(7, DEVICE, 0, b"\x16\x03\x03").hex()],
            ["to_node", frame(7, DEVICE, CLOSE).hex()],
            ["to_connect", frame(7, DEVICE, CLOSE).hex()],
        ],
        "error": None,
    },
    {
        "name": "two_streams_interleave",
        "frames": [
            ["to_node", frame(8, DEVICE, OPEN).hex()],
            ["to_node", frame(9, PUBLIC, OPEN, HELLO).hex()],
            ["to_connect", frame(9, PUBLIC, 0, b"srv").hex()],
            ["to_connect", frame(8, DEVICE, 0, b"dev").hex()],
            ["to_node", frame(8, DEVICE, RESET).hex()],
            ["to_connect", frame(9, PUBLIC, CLOSE).hex()],
        ],
        "error": None,
    },
    {
        "name": "data_before_open",
        "frames": [["to_node", frame(10, DEVICE, 0, b"x").hex()]],
        "error": [0, "not_open"],
    },
    {
        "name": "the_node_opens_a_stream",
        "frames": [["to_connect", frame(11, DEVICE, OPEN).hex()]],
        "error": [0, "open_by_node"],
    },
    {
        "name": "open_twice",
        "frames": [
            ["to_node", frame(12, DEVICE, OPEN).hex()],
            ["to_node", frame(12, DEVICE, OPEN).hex()],
        ],
        "error": [1, "already_open"],
    },
    {
        "name": "kind_changes_inside_a_stream",
        "frames": [
            ["to_node", frame(13, DEVICE, OPEN).hex()],
            ["to_connect", frame(13, PUBLIC, 0, b"x").hex()],
        ],
        "error": [1, "kind_mismatch"],
    },
    {
        "name": "data_after_close_of_that_side",
        "frames": [
            ["to_node", frame(14, DEVICE, OPEN).hex()],
            ["to_node", frame(14, DEVICE, CLOSE).hex()],
            ["to_node", frame(14, DEVICE, 0, b"x").hex()],
        ],
        "error": [2, "closed"],
    },
    {
        "name": "a_stream_id_is_not_reused_after_reset",
        "frames": [
            ["to_node", frame(15, DEVICE, OPEN).hex()],
            ["to_connect", frame(15, DEVICE, RESET).hex()],
            ["to_node", frame(15, DEVICE, OPEN).hex()],
        ],
        "error": [2, "reused"],
    },
]


def main():
    out = {
        "header_bytes": 8,
        "max_payload": MAX_PAYLOAD,
        "flags": {"open": OPEN, "close": CLOSE, "reset": RESET},
        "kinds": {"device": DEVICE, "public": PUBLIC, "acme": ACME},
        "frames": [
            {
                "name": name,
                "hex": frame(stream, kind, flags, payload).hex(),
                "stream": stream,
                "kind": kind,
                "flags": flags,
                "payload_hex": payload.hex(),
            }
            for name, stream, kind, flags, payload in VALID
        ],
        "invalid": [{"name": n, "hex": b.hex(), "reason": r} for n, b, r in INVALID],
        "sequences": SEQUENCES,
    }
    (DIR / "frames.json").write_text(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
