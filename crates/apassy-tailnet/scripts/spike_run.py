#!/usr/bin/env python3
"""The runtime numbers of the tailnet spike (docs/design/spike-tsnet.md).

  spike_run.py measure    --spike BIN --out DIR [--tag TAG]
  spike_run.py round-trip --spike BIN --out DIR [--tag TAG]

measure: signal dispositions, crash probes, termination by SIGTERM/SIGINT/SIGHUP,
threads and memory at idle (Go runtime only; a node started offline; a node up),
the login URL of a node without an auth key, and, with TS_A_AUTH, the time to up
(cold and warm), the loopback LocalAPI, the state directory, and the tsnet log.

round-trip (Linux job): two nodes of tailnet A (TS_A_AUTH), then node A shared to
tailnet B through the Tailscale API (TS_A_API, TS_B_API) and node B (TS_B_AUTH)
connecting across tailnets. Without the API tokens, B checks that it cannot reach
A without a share.

Secrets come from the environment and reach the spike only on stdin. A missing
secret skips its part and the results say so. The results never hold a key, a
login or invite URL, an e-mail address (the local part is masked), or a tsnet log:
OUT/<mode>.json, and a Markdown summary on stdout for the job summary.
"""

import argparse
import json
import os
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

OFFLINE = "http://127.0.0.1:1"
API = "https://api.tailscale.com/api/v2"
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)")
SECRETS = ("TS_A_AUTH", "TS_B_AUTH", "TS_A_API", "TS_B_API")


def mask(value):
    """The local part of e-mail addresses (tailnet names, logins) becomes ***."""
    if isinstance(value, str):
        return EMAIL.sub(lambda match: "***@" + match.group(1), value)
    if isinstance(value, list):
        return [mask(item) for item in value]
    if isinstance(value, dict):
        return {key: mask(item) for key, item in value.items()}
    return value


def secret(name):
    value = os.environ.get(name, "").strip()
    return value or None


def child_env(extra=None):
    """No TS_* variable reaches the spike: secrets go on stdin."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TS_") and k != "TSNET_FORCE_LOGIN"}
    env.update(extra or {})
    return env


class Spike:
    """One spike process with its JSON events."""

    def __init__(self, binary, args, key=None, env=None):
        self.proc = subprocess.Popen(
            [binary, *map(str, args)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env(env),
            start_new_session=True,
            text=True,
        )
        self.events = queue.Queue()
        self.seen = []
        self.stderr = []
        if key:
            self.proc.stdin.write(key + "\n")
        self.proc.stdin.close()
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self):
        for line in self.proc.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            self.seen.append(event)
            self.events.put(event)

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr.append(line.rstrip("\n"))
            del self.stderr[:-200]

    @property
    def pid(self):
        return self.proc.pid

    def wait_event(self, names, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = self.events.get(timeout=0.5)
            except queue.Empty:
                if self.proc.poll() is not None and self.events.empty():
                    return None
                continue
            if event.get("event") in names:
                return event
            if event.get("event") == "error":
                return event
        return None

    def wait(self, timeout):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self):
        if self.proc.poll() is None:
            os.kill(self.proc.pid, signal.SIGTERM)
            if self.wait(15) is None:
                os.kill(self.proc.pid, signal.SIGKILL)
                self.wait(5)
        return self.proc.returncode


def exit_of(code):
    if code is None:
        return {"exit": None, "signal": None}
    if code < 0:
        return {"exit": None, "signal": signal.Signals(-code).name}
    return {"exit": code, "signal": None}


def sample(pid):
    if sys.platform.startswith("linux"):
        status = Path(f"/proc/{pid}/status").read_text()

        def field(key):
            match = re.search(rf"^{key}:\s+(\d+)", status, re.M)
            return int(match.group(1)) if match else None

        masks = {k: re.search(rf"^{k}:\s+(\S+)", status, re.M).group(1) for k in ("SigIgn", "SigCgt")}
        return {"threads": field("Threads"), "rss_kib": field("VmRSS"), "hwm_kib": field("VmHWM"), **masks}
    threads = subprocess.run(["ps", "-M", "-p", str(pid)], capture_output=True, text=True).stdout
    rss = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    vmmap = subprocess.run(["vmmap", "--summary", str(pid)], capture_output=True, text=True).stdout
    footprint = re.search(r"Physical footprint:\s+(\S+)", vmmap)
    return {
        "threads": max(len(threads.strip().splitlines()) - 1, 0),
        "rss_kib": int(rss) if rss.isdigit() else None,
        "footprint": footprint.group(1) if footprint else None,
    }


def offline_serve(binary, directory, hostname):
    return Spike(
        binary,
        ["serve", "--dir", directory, "--hostname", hostname, "--no-auth-key", "--no-wait", "--control-url", OFFLINE],
    )


def crash_reports_since(start):
    folder = Path.home() / "Library/Logs/DiagnosticReports"
    if not folder.is_dir():
        return []
    return sorted(p.name for p in folder.iterdir() if "apassy-tailnet-spike" in p.name and p.stat().st_mtime >= start)


def probe(binary, args, env, timeout=60):
    start = time.time()
    try:
        done = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=timeout, env=child_env(env), start_new_session=True
        )
        result = exit_of(done.returncode)
        stderr = done.stderr
    except subprocess.TimeoutExpired as expired:
        result = {"exit": None, "signal": None, "timed_out": True}
        stderr = expired.stderr.decode(errors="replace") if isinstance(expired.stderr, bytes) else (expired.stderr or "")
    result["seconds"] = round(time.time() - start, 2)
    result["rust_panic_message"] = "panicked at" in stderr
    result["rust_stack_overflow_message"] = "has overflowed its stack" in stderr
    result["go_panic_message"] = bool(re.search(r"^panic: ", stderr, re.M))
    result["go_traceback"] = bool(re.search(r"^goroutine \d+ \[|^runtime stack:|^SIG[A-Z]+: ", stderr, re.M))
    result["stderr_head"] = mask(stderr.splitlines()[:12])
    if sys.platform == "darwin":
        time.sleep(5)
        result["macos_crash_reports"] = crash_reports_since(start)
    return result


def measure(args, tmp):
    binary = args.spike
    results = {"mode": "measure", "tag": args.tag}

    signals = subprocess.run([binary, "signals", "--dir", tmp / "signals"], capture_output=True, text=True, timeout=120, env=child_env())
    events = [json.loads(line) for line in signals.stdout.splitlines() if line.startswith("{")]
    results["signals"] = {"exit": signals.returncode, "events": events}

    crashes = {}
    for kind in ("rust-panic", "rust-stack-overflow", "rust-segv", "go-panic"):
        for traceback in ("default", "crash"):
            env = {} if traceback == "default" else {"GOTRACEBACK": "crash"}
            crashes[f"{kind} GOTRACEBACK={traceback}"] = probe(binary, ["crash", kind, "--dir", tmp / f"crash-{kind}-{traceback}"], env)
    results["crashes"] = crashes

    idle = Spike(binary, ["idle"])
    if idle.wait_event({"idle"}, 30):
        time.sleep(10)
        results["idle_no_node"] = sample(idle.pid)
    idle.stop()

    node = offline_serve(binary, tmp / "offline", "apassy-spike-offline")
    if node.wait_event({"started"}, 60):
        time.sleep(30)
        results["idle_offline_node"] = sample(node.pid)
    else:
        results["idle_offline_node"] = {"error": mask(node.stderr[-5:])}
    node.stop()

    terminations = {}
    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        node = offline_serve(binary, tmp / f"term-{name}", "apassy-spike-term")
        if not node.wait_event({"started"}, 60):
            terminations[name] = {"error": "the node did not start", "stderr": mask(node.stderr[-5:])}
            node.stop()
            continue
        start = time.monotonic()
        os.kill(node.pid, getattr(signal, name))
        code = node.wait(15)
        terminations[name] = {**exit_of(code), "seconds": round(time.monotonic() - start, 2), "still_running": code is None}
        node.stop()
    results["terminations"] = terminations

    login = subprocess.run(
        [binary, "login-url", "--dir", tmp / "login", "--hostname", f"apassy-spike-login-{args.tag}", "--wait", "45"],
        capture_output=True, text=True, timeout=120, env=child_env(),
    )
    event = next((json.loads(l) for l in login.stdout.splitlines() if '"login_url"' in l), None)
    results["login_url"] = mask(
        {"present": event.get("present"), "host": event.get("host"), "ms": event.get("ms"), "backend_state": event["status"]["backend_state"]}
        if event else {"error": login.stderr.strip()[-300:]}
    )

    key = secret("TS_A_AUTH") if args.online else None
    if not key:
        results["online"] = {"skipped": "TS_A_AUTH is not set or online is off"}
        return results
    online = {}
    a_dir = tmp / "node-a"
    hostname = f"apassy-spike-{'mac' if sys.platform == 'darwin' else 'linux'}-{args.tag}"
    log = tmp / "node-a.log"
    node = Spike(
        binary,
        ["serve", "--dir", a_dir, "--hostname", hostname, "--ephemeral", "--check-loopback", "--log-file", log, "--up-timeout", "150"],
        key=key,
    )
    up = node.wait_event({"up"}, 180)
    if not up or up.get("event") != "up":
        online["cold_up"] = {"error": mask((up or {}).get("error") or node.stderr[-5:])}
        node.stop()
        results["online"] = online
        return results
    online["cold_up_ms"] = up["ms"]
    online["status"] = mask({k: up["status"].get(k) for k in ("backend_state", "version", "health", "peers", "auth_url_present")})
    loopback = node.wait_event({"loopback"}, 30)
    online["loopback"] = mask({k: v for k, v in (loopback or {}).items() if k != "event"})
    time.sleep(30)
    online["idle_up_node"] = sample(node.pid)
    state = subprocess.run([binary, "state", "--dir", a_dir], capture_output=True, text=True, timeout=30, env=child_env())
    online["state"] = next((json.loads(l) for l in state.stdout.splitlines() if l.startswith("{")), None)
    online["cold_exit"] = exit_of(node.stop())
    stable_id = up["status"].get("stable_id")

    warm = Spike(binary, ["serve", "--dir", a_dir, "--hostname", hostname, "--no-auth-key", "--up-timeout", "120"])
    up = warm.wait_event({"up"}, 150)
    online["warm_up_ms"] = up["ms"] if up and up.get("event") == "up" else None
    if online["warm_up_ms"] is None:
        online["warm_up_error"] = mask((up or {}).get("error") or warm.stderr[-5:])
    warm.stop()

    text = log.read_text(errors="replace") if log.exists() else ""
    online["log"] = {
        "lines": len(text.splitlines()),
        "auth_key_in_log": key in text,
        "tskey_in_log": "tskey-" in text,
        "mentions_log_tailscale_com": sum("log.tailscale.com" in line for line in text.splitlines()),
    }
    if stable_id and secret("TS_A_API"):
        online["device_deleted"] = api(secret("TS_A_API"), "DELETE", f"/device/{stable_id}")[0]
    results["online"] = online
    return results


def api(token, method, path, body=None):
    request = urllib.request.Request(
        API + path,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "apassy-tailnet-spike"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as error:
        return error.code, mask(error.read().decode(errors="replace")[:300])
    except urllib.error.URLError as error:
        return 0, str(error.reason)


def dial(binary, directory, hostname, key, to, attempts, timeout):
    node = Spike(binary, ["dial", "--dir", directory, "--hostname", hostname, "--ephemeral", "--to", to, "--attempts", attempts, "--up-timeout", "150"], key=key)
    code = node.wait(timeout)
    if code is None:
        node.stop()
    ups = [e for e in node.seen if e.get("event") == "up"]
    trips = [e for e in node.seen if e.get("event") == "round_trip"]
    failures = [e for e in node.seen if e.get("event") == "dial_failed"]
    return {
        "ok": bool(trips),
        "up_ms": ups[0]["ms"] if ups else None,
        "round_trip_ms": trips[0]["ms"] if trips else None,
        "attempts": trips[0]["attempt"] if trips else len(failures),
        "last_error": mask(failures[-1]["error"]) if failures and not trips else None,
        "timed_out": code is None,
        "stable_id": ups[0]["status"].get("stable_id") if ups else None,
        **exit_of(code),
    }


def accepted_peers(node, since):
    return [
        mask({"whois_ok": "error" not in e["peer"], "login": e["peer"].get("login"), "tags": e["peer"].get("tags"), "whois_ms": e.get("whois_ms")})
        for e in node.seen[since:]
        if e.get("event") == "accepted"
    ]


def round_trip(args, tmp):
    binary = args.spike
    results = {"mode": "round-trip", "tag": args.tag}
    a_key, b_key, a_api, b_api = (secret(name) for name in SECRETS)
    if not args.online or not a_key:
        results["skipped"] = "TS_A_AUTH is not set or online is off"
        return results
    cleanup = []
    a = Spike(binary, ["serve", "--dir", tmp / "rt-a", "--hostname", f"apassy-spike-a-{args.tag}", "--ephemeral", "--up-timeout", "150"], key=a_key)
    try:
        up = a.wait_event({"up"}, 180)
        if not up or up.get("event") != "up":
            results["node_a"] = {"error": mask((up or {}).get("error") or a.stderr[-5:])}
            return results
        status = up["status"]
        a_ip = next((ip for ip in status["ips"] if "." in ip), status["ips"][0])
        a_name = (status.get("dns_name") or "").rstrip(".")
        cleanup.append((a_api, status.get("stable_id")))
        results["node_a"] = {"up_ms": up["ms"], "tailnet": mask(status.get("tailnet"))}

        seen = len(a.seen)
        same = dial(binary, tmp / "rt-a2", f"apassy-spike-a2-{args.tag}", a_key, f"{a_ip}:8443", 10, 240)
        cleanup.append((a_api, same.pop("stable_id")))
        time.sleep(1)
        same["peers_seen_by_a"] = accepted_peers(a, seen)
        results["same_tailnet"] = same

        if not b_key:
            results["cross_tailnet"] = {"skipped": "TS_B_AUTH is not set"}
            return results
        if not (a_api and b_api):
            negative = dial(binary, tmp / "rt-b", f"apassy-spike-b-{args.tag}", b_key, f"{a_ip}:8443", 1, 120)
            cleanup.append((b_api, negative.pop("stable_id")))
            results["cross_tailnet"] = {
                "skipped": "TS_A_API or TS_B_API is not set: no share",
                "reachable_without_share": negative["ok"],
                "without_share": negative,
            }
            return results

        share = {}
        code, body = api(a_api, "POST", f"/device/{status.get('stable_id')}/device-invites", [{"multiUse": False, "allowExit": False}])
        share["invite_status"] = code
        invite = body[0] if code == 200 and isinstance(body, list) and body else None
        if not invite or not invite.get("inviteUrl"):
            share["invite_error"] = body if code != 200 else "no inviteUrl in the answer"
            results["cross_tailnet"] = share
            return results
        code, body = api(b_api, "POST", "/device-invites/-/accept", {"invite": invite["inviteUrl"]})
        share["accept_status"] = code
        if code != 200:
            share["accept_error"] = body
        seen = len(a.seen)
        cross = dial(binary, tmp / "rt-b", f"apassy-spike-b-{args.tag}", b_key, f"{a_ip}:8443", 20, 300)
        cleanup.append((b_api, cross.pop("stable_id")))
        if not cross["ok"] and a_name:
            by_name = dial(binary, tmp / "rt-b2", f"apassy-spike-b2-{args.tag}", b_key, f"{a_name}:8443", 5, 180)
            cleanup.append((b_api, by_name.pop("stable_id")))
            share["by_magicdns_name"] = by_name
        time.sleep(1)
        cross["peers_seen_by_a"] = accepted_peers(a, seen)
        share["round_trip"] = cross
        if invite.get("id"):
            share["invite_deleted"] = api(a_api, "DELETE", f"/device-invites/{invite['id']}")[0]
        results["cross_tailnet"] = share
        return results
    finally:
        results["node_a_exit"] = exit_of(a.stop())
        results["devices_deleted"] = [api(token, "DELETE", f"/device/{device}")[0] for token, device in cleanup if token and device]


def row(name, value):
    return f"| {name} | {value} |"


def summary(results):
    lines = [f"### Run: {results['mode']}", "", "| Check | Result |", "| --- | --- |"]
    for key, value in results.items():
        if key in ("mode", "tag", "signals"):
            continue
        if key == "crashes":
            for probe_name, probe_result in value.items():
                how = probe_result.get("signal") or f"exit {probe_result.get('exit')}"
                marks = [m for m in ("rust_panic_message", "rust_stack_overflow_message", "go_panic_message", "go_traceback") if probe_result.get(m)]
                lines.append(row(f"crash {probe_name}", f"{how}; {', '.join(marks) or 'no message'}"))
            continue
        lines.append(row(key, f"`{json.dumps(value, sort_keys=True)[:400]}`"))
    if "signals" in results:
        for event in results["signals"]["events"]:
            if event.get("event") == "signals":
                table = ", ".join(f"{s['signal']}={s['disposition']}" for s in event["signals"] if s["disposition"] != "default")
                lines.append(row(f"signals {event['when']} (non-default)", table or "all default"))
            elif event.get("event") in ("sigpipe", "proc_signal_masks"):
                lines.append(row(event["event"], f"`{json.dumps(event)[:300]}`"))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["measure", "round-trip"])
    parser.add_argument("--spike", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--tag", default=str(int(time.time())))
    parser.add_argument("--online", action="store_true", help="use the TS_* secrets")
    args = parser.parse_args()
    args.spike = str(Path(args.spike).resolve())
    if not re.fullmatch(r"[a-z0-9-]{1,30}", args.tag):
        parser.error("--tag must be 1 to 30 of a-z, 0-9, -")
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apassy-tailnet-spike-") as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        results = measure(args, tmp) if args.mode == "measure" else round_trip(args, tmp)
    results = mask(results)
    for name in SECRETS:
        value = secret(name)
        if value and value in json.dumps(results):
            raise SystemExit(f"{name} would be in the results; nothing written")
    args.out.joinpath(f"{args.mode}.json").write_text(json.dumps(results, indent=2, default=str) + "\n")
    print(summary(results))


if __name__ == "__main__":
    main()
