#!/usr/bin/env python3
"""The listener of scripts/mac-target.sh: one short answer per GET, optionally over TLS.

    python3 -I mac-target.py HOST PORT [CERT KEY]

Spike only (plan s8 unit T0). It binds HOST only (the Mac's tailnet address) and logs each
caller's address and the time, so the log shows that the iPhone's own node reached the Mac.
"""

import http.server
import ssl
import sys
import time


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"apassy tailnet spike target\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        stamp = time.strftime("%H:%M:%S")
        sys.stderr.write(f"{stamp} {self.client_address[0]} {fmt % args}\n")


def main():
    if len(sys.argv) not in (3, 5):
        print("usage: mac-target.py HOST PORT [CERT KEY]", file=sys.stderr)
        return 2
    host, port = sys.argv[1], int(sys.argv[2])
    server = http.server.ThreadingHTTPServer((host, port), Handler)
    if len(sys.argv) == 5:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(sys.argv[3], sys.argv[4])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Listening on {host}:{port} (Ctrl-C stops it)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
