// Minimal CDP WebSocket client, adapted from the 2026-10-31 suggestion audit.
export const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const CDP_PORT = Number(process.env.APASSY_CDP_PORT || 9371);
export async function connect(url) {
  const ws = new WebSocket(url);
  await new Promise((r, j) => {
    ws.addEventListener("open", r, { once: true });
    ws.addEventListener("error", j, { once: true });
  });
  let seq = 0;
  const pending = new Map(),
    events = [];
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data);
    if (m.id) {
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      clearTimeout(p.timer);
      m.error ? p.j(new Error(JSON.stringify(m.error))) : p.r(m.result);
    } else events.push(m);
  });
  return {
    events,
    close: () => ws.close(),
    send(method, params = {}, sessionId) {
      const id = ++seq;
      return new Promise((r, j) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          j(new Error("CDP timeout " + method));
        }, 30000);
        pending.set(id, { r, j, timer });
        ws.send(
          JSON.stringify({
            id,
            method,
            params,
            ...(sessionId ? { sessionId } : {}),
          }),
        );
      });
    },
    async eval(expression, contextId) {
      const result = await this.send("Runtime.evaluate", {
        expression,
        awaitPromise: true,
        returnByValue: true,
        userGesture: true,
        ...(contextId ? { contextId } : {}),
      });
      if (result.exceptionDetails)
        throw new Error(JSON.stringify(result.exceptionDetails));
      return result.result.value;
    },
  };
}
export async function browser() {
  const v = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`)).json();
  return connect(v.webSocketDebuggerUrl);
}
export async function targets() {
  return await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`)).json();
}
export async function worker() {
  let t = (await targets()).find(
    (t) =>
      t.type === "service_worker" &&
      t.url.includes("bbnpgnjnfjlbgggmpnhejpmfjhmmhiih"),
  );
  if (!t) {
    const b = await browser();
    const wake = await b.send("Target.createTarget", {
      url: "chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/popup.html",
    });
    await delay(300);
    t = (await targets()).find(
      (t) =>
        t.type === "service_worker" &&
        t.url.includes("bbnpgnjnfjlbgggmpnhejpmfjhmmhiih"),
    );
    await b.send("Target.closeTarget", { targetId: wake.targetId });
    b.close();
  }
  if (!t) throw new Error("worker absent");
  const c = await connect(t.webSocketDebuggerUrl);
  await c.send("Runtime.enable");
  return c;
}
export async function page(url) {
  const b = await browser();
  const t = await b.send("Target.createTarget", { url });
  b.close();
  for (let i = 0; i < 100; i++) {
    const p = (await targets()).find((x) => x.id === t.targetId);
    if (p) {
      const c = await connect(p.webSocketDebuggerUrl);
      c.id = p.id;
      await c.send("Runtime.enable");
      await c.send("Page.enable");
      await c.send("Log.enable");
      return c;
    }
    await delay(50);
  }
  throw new Error("no page");
}
