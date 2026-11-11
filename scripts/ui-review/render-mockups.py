#!/usr/bin/env python3
"""Render the frames of the design mockups as PNG files, one per panel.

Usage: render-mockups.py OUT_DIR MOCKUP.html [MOCKUP.html ...]

Starts a headless Chromium (CHROMIUM, default `chromium`) and drives it over the
DevTools protocol (python3-websocket). Each panel (the parent of a `.plabel`) becomes
`<mockup>-<code>.png` (code: the text before " · ", such as 12a); each whole-window
frame (`section.frame > .win`) becomes `<mockup>-<frame number>.png`. Every PNG is
WIDTH px wide (default 1100). The page is rendered in light mode.

The mockups name the project owner in their fixtures; for the review images the
first name is replaced by the synthetic name of the demo build (NAME_FROM, NAME_TO).
Nothing is loaded from the network: the mockups are self-contained files.
"""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import websocket  # python3-websocket

WIDTH = int(os.environ.get("WIDTH", "1100"))
NAME_FROM = os.environ.get("NAME_FROM", "Rafal")
NAME_TO = os.environ.get("NAME_TO", "Alex")

COLLECT = r"""
(() => {
  const from = %s, to = %s;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (n.nodeValue.includes(from)) n.nodeValue = n.nodeValue.split(from).join(to);
    if (n.nodeValue.includes(from.toLowerCase())) n.nodeValue = n.nodeValue.split(from.toLowerCase()).join(to.toLowerCase());
  }
  document.querySelectorAll('.av').forEach(a => { if (a.textContent.trim() === from[0]) a.textContent = to[0]; });
  const out = [];
  document.querySelectorAll('section.frame').forEach((frame, i) => {
    const num = frame.querySelector('.fnum');
    const fcode = num ? num.textContent.trim() : String(i + 1);
    frame.querySelectorAll(':scope > .win').forEach((win, j) => {
      const r = win.getBoundingClientRect();
      out.push({code: fcode + (j ? '-' + (j + 1) : ''), x: r.left + scrollX, y: r.top + scrollY, w: r.width, h: r.height});
    });
    frame.querySelectorAll('.plabel').forEach(label => {
      const card = label.parentElement;
      const code = (label.firstChild ? label.firstChild.textContent : label.textContent).split('·')[0].trim();
      const r = card.getBoundingClientRect();
      out.push({code, x: r.left + scrollX, y: r.top + scrollY, w: r.width, h: r.height});
    });
  });
  return JSON.stringify(out);
})()
"""


class Tab:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=60)
        self.next_id = 0

    def call(self, method, **params):
        self.next_id += 1
        self.ws.send(json.dumps({"id": self.next_id, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.next_id:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    port = free_port()
    profile = tempfile.mkdtemp(prefix="mockup-chromium-")
    browser = subprocess.Popen(
        [os.environ.get("CHROMIUM", "chromium"), "--headless=new", "--no-sandbox",
         "--disable-gpu", "--no-first-run", "--hide-scrollbars", f"--user-data-dir={profile}",
         f"--remote-debugging-port={port}", "--remote-allow-origins=*", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                page = next(t for t in tabs if t["type"] == "page")
                break
            except Exception:
                time.sleep(0.2)
        else:
            sys.exit("render-mockups: Chromium did not start")
        tab = Tab(page["webSocketDebuggerUrl"])
        tab.call("Page.enable")
        tab.call("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "light"}])
        tab.call("Emulation.setDeviceMetricsOverride", width=1440, height=1000, deviceScaleFactor=1, mobile=False)
        count = 0
        for path in sys.argv[2:]:
            name = os.path.basename(path).replace("-mockup.html", "").replace(".html", "")
            tab.call("Page.navigate", url="file://" + os.path.abspath(path))
            time.sleep(2.0)
            expr = COLLECT % (json.dumps(NAME_FROM), json.dumps(NAME_TO))
            rects = json.loads(tab.call("Runtime.evaluate", expression=expr, returnByValue=True)["result"]["value"])
            seen = {}
            for r in rects:
                code = r["code"]
                seen[code] = seen.get(code, 0) + 1
                if seen[code] > 1:
                    code = f"{code}-{seen[code]}"
                scale = WIDTH / r["w"]
                shot = tab.call("Page.captureScreenshot", format="png", captureBeyondViewport=True,
                                clip={"x": r["x"], "y": r["y"], "width": r["w"], "height": r["h"], "scale": scale})
                file = os.path.join(out, f"{name}-{code}.png")
                with open(file, "wb") as f:
                    f.write(base64.b64decode(shot["data"]))
                count += 1
            print(f"{name}: {len(rects)} panels")
        print(f"rendered {count} mockup images in {out}")
    finally:
        browser.terminate()
        browser.wait(timeout=10)


if __name__ == "__main__":
    main()
