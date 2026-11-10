"""Talk to apassy-browser-host or the app's browser socket like a browser would.

  native_frame.py host [ORIGIN]   run /usr/lib/apassy/apassy-browser-host as a child of
                                  this (non-browser) process and send one passkey_get
  native_frame.py socket PATH     connect to the app's browser.sock and send the same
                                  packet directly (no host)

Prints only the answer's "code" (never data). Synthetic values only.
"""
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import uuid

ORIGIN = "http://localhost:4174"
EXTENSION = "chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/"


def packet():
    challenge = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    client = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": ORIGIN, "crossOrigin": False},
        separators=(",", ":"),
    ).encode()
    return {
        "v": 1,
        "cmd": "passkey_get",
        "rid": str(uuid.uuid4()),
        "origin": ORIGIN,
        "rp_id": "localhost",
        "client_data_json": base64.b64encode(client).decode(),
        "allowed": [],
    }


def via_host():
    body = json.dumps(packet()).encode()
    child = subprocess.Popen(
        ["/usr/lib/apassy/apassy-browser-host", EXTENSION],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    child.stdin.write(struct.pack("<I", len(body)) + body)
    child.stdin.flush()
    size = child.stdout.read(4)
    if len(size) != 4:
        print("no-answer exit=%s" % child.wait())
        return
    answer = json.loads(child.stdout.read(struct.unpack("<I", size)[0]))
    child.stdin.close()
    child.wait()
    print(answer.get("code"))


def via_socket(path):
    line = json.dumps(packet()).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(20)
        s.connect(path)
        s.sendall(line)
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    print(json.loads(data).get("code") if data else "no-answer")


if __name__ == "__main__":
    if sys.argv[1] == "host":
        via_host()
    else:
        via_socket(sys.argv[2])
