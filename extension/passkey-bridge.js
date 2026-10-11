// The relay between passkey-page.js (MAIN world) and the service worker. It
// runs in the ISOLATED world of the top frame, at document_start, only after
// the owner turned on passkeys in the popup.
//
// One runtime port per request. The service worker reads the origin, the tab,
// the frame, and the document from that port (the browser fills them in), never
// from what the page sends. This script decides nothing: it caps the size,
// forwards, and closes the port at a cancel or when the page goes away. The
// browser closes the port at a navigation, so a late answer has nowhere to go.

(() => {
  "use strict";

  if (window.top !== window) return;

  const REQUEST = "apassy-passkey-request";
  const RESPONSE = "apassy-passkey-response";
  const PORT = "apassy-passkey";
  const MAX_DETAIL = 64 * 1024;
  const RID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const ERRORS = ["NotAllowedError", "InvalidStateError", "AbortError"];
  // At most this many open ports from one page. The service worker keeps one
  // request per tab anyway.
  const MAX_OPEN = 4;

  const ports = new Map();

  function reply(rid, body) {
    window.dispatchEvent(new CustomEvent(RESPONSE, { detail: JSON.stringify({ ...body, rid }) }));
  }

  // Only the shapes that the page script reads.
  function answerFor(message) {
    if (!message || typeof message !== "object") return { kind: "error", name: "NotAllowedError" };
    if (message.kind === "fallback") return { kind: "fallback" };
    if (message.kind === "error") {
      return { kind: "error", name: ERRORS.includes(message.name) ? message.name : "NotAllowedError" };
    }
    if (message.kind === "result" && (message.op === "get" || message.op === "create") &&
        message.credential && typeof message.credential === "object") {
      return { kind: "result", op: message.op, credential: message.credential };
    }
    return { kind: "error", name: "NotAllowedError" };
  }

  function close(rid) {
    const port = ports.get(rid);
    if (!port) return;
    ports.delete(rid);
    try { port.disconnect(); } catch (_) { /* already closed */ }
  }

  function start(rid, message) {
    // The page waits for this before it gives up on the bridge.
    reply(rid, { kind: "ack" });
    if (ports.size >= MAX_OPEN) {
      reply(rid, { kind: "error", name: "NotAllowedError" });
      return;
    }
    let port;
    try {
      port = chrome.runtime.connect({ name: PORT });
    } catch (_) {
      // The extension was reloaded or removed: nothing reached Apassy.
      reply(rid, { kind: "fallback" });
      return;
    }
    ports.set(rid, port);
    let answered = false;
    port.onMessage.addListener((answer) => {
      if (answered) return;
      answered = true;
      close(rid);
      reply(rid, answerFor(answer));
    });
    port.onDisconnect.addListener(() => {
      if (answered) return;
      answered = true;
      ports.delete(rid);
      // Ended without an answer: the service worker stopped, or it ended the
      // request. Never a fallback here, the owner may have seen a dialog.
      reply(rid, { kind: "error", name: "NotAllowedError" });
    });
    const request = { op: message.op, options: message.options };
    if (message.mediation !== undefined) request.mediation = message.mediation;
    port.postMessage(request);
  }

  window.addEventListener(REQUEST, (event) => {
    const detail = event.detail;
    if (typeof detail !== "string" || detail.length > MAX_DETAIL) return;
    let message;
    try {
      message = JSON.parse(detail);
    } catch (_) {
      return;
    }
    if (!message || typeof message !== "object" || typeof message.rid !== "string" || !RID.test(message.rid)) return;
    const { rid } = message;
    if (message.op === "cancel") {
      close(rid);
      return;
    }
    if ((message.op !== "get" && message.op !== "create") || ports.has(rid) ||
        !message.options || typeof message.options !== "object") return;
    start(rid, message);
  });

  // The page goes away (also into the back/forward cache): cancel everything.
  window.addEventListener("pagehide", () => {
    for (const rid of [...ports.keys()]) {
      close(rid);
      reply(rid, { kind: "error", name: "AbortError" });
    }
  });
})();
