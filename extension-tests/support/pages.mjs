// Test pages, served on 127.0.0.1 and localhost (two origins of one server).

import http from "node:http";

const page = (title, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>input { display: block; margin: 4px 0; }</style></head>
<body>${body}</body></html>`;

const PAGES = {
  // A plain login form, with a search box, a hidden trap field, and a
  // newsletter field around it.
  "/login": page("Sign in", `
    <input type="search" name="q" id="search" placeholder="Search">
    <form id="login" action="/done" method="post" onsubmit="return false">
      <input type="text" name="email_confirm" id="trap" style="display:none">
      <input type="text" name="username" id="username" autocomplete="username">
      <input type="password" name="password" id="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
    <form id="news" onsubmit="return false">
      <input type="email" name="newsletter" id="newsletter" placeholder="Your email">
    </form>`),

  // Inputs that keep their value in page state, like a controlled React
  // input: the page installs its own value property on each input (as React
  // does to track the value) and takes a new value only from an input event
  // that brings a value the tracker has not seen. A render puts the state back
  // into the fields, so a value without the events is lost.
  "/react": page("React sign in", `
    <form id="login" onsubmit="return false">
      <input type="email" id="username" name="email">
      <input type="password" id="password" name="pass">
    </form>
    <pre id="state"></pre>
    <script>
      const state = { email: "", pass: "" };
      const native = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
      const render = () => {
        for (const el of document.querySelectorAll("#login input")) el.value = state[el.name];
        document.getElementById("state").textContent = JSON.stringify({ email: state.email.length, pass: state.pass.length });
      };
      for (const el of document.querySelectorAll("#login input")) {
        let tracked = "";
        Object.defineProperty(el, "value", {
          configurable: true,
          get() { return native.get.call(this); },
          set(v) { tracked = String(v); native.set.call(this, v); },
        });
        el.addEventListener("input", () => {
          const now = native.get.call(el);
          if (now === tracked) return;
          tracked = now;
          state[el.name] = now;
          render();
        });
        el.addEventListener("focus", () => setTimeout(render, 0));
      }
      window.appState = state;
      render();
    </script>`),

  // The first step of a login that asks only for the username.
  "/step1": page("Sign in: step 1", `
    <input type="text" name="q" id="search" placeholder="Search">
    <form id="step1" onsubmit="return false">
      <input type="email" name="identifier" id="username" autocomplete="username">
      <button type="submit">Next</button>
    </form>`),

  // A login form inside an open shadow root.
  "/shadow": page("Shadow sign in", `
    <login-box id="box"></login-box>
    <script>
      customElements.define("login-box", class extends HTMLElement {
        constructor() {
          super();
          this.attachShadow({ mode: "open" }).innerHTML = \`
            <form onsubmit="return false">
              <input type="text" name="login" id="username">
              <input type="password" name="secret" id="password">
              <button>Sign in</button>
            </form>\`;
        }
      });
    </script>`),

  // A sign-up form with a new password, then a sign-in form with the current
  // password.
  "/new-and-current": page("Join or sign in", `
    <form id="join" onsubmit="return false">
      <input type="email" name="join_email" id="join-email" autocomplete="email">
      <input type="password" name="new" id="new-password" autocomplete="new-password">
    </form>
    <form id="signin" onsubmit="return false">
      <input type="email" name="email" id="username" autocomplete="username">
      <input type="password" name="current" id="password" autocomplete="current-password">
    </form>`),

  // A sign-up form that asks for the new password twice, with a search box
  // and a newsletter field around it that must stay empty.
  "/signup": page("Create an account", `
    <input type="text" name="q" id="search" placeholder="Search">
    <form id="signup" onsubmit="return false">
      <input type="email" name="email" id="email" autocomplete="email">
      <input type="password" name="password" id="new-password" autocomplete="new-password">
      <input type="password" name="confirm" id="confirm-password" autocomplete="new-password">
      <button type="submit">Create account</button>
    </form>
    <form id="news" onsubmit="return false">
      <input type="email" name="newsletter" id="newsletter" placeholder="Your email">
    </form>`),

  // A sign-in form that the owner fills by hand, then saves to Apassy. No
  // autocomplete tokens: the fields are found by their names.
  "/typed": page("Sign in by hand", `
    <input type="text" name="q" id="search" placeholder="Search">
    <form id="login" onsubmit="return false">
      <input type="text" name="login" id="username">
      <input type="password" name="pass" id="password">
      <button type="submit">Sign in</button>
    </form>`),

  "/journey-login": page("Synthetic account sign-in", `
    <form id="login">
      <label>Username<input id="username" name="username" autocomplete="username"></label>
      <label>Password<input id="password" name="password" type="password" autocomplete="current-password"></label>
      <button>Sign in</button>
    </form><p id="status" role="status"></p>
    <script>
      document.querySelector("form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const response = await fetch("/journey-auth", { method: "POST", headers: {"content-type":"application/json"}, body: JSON.stringify({ username: document.querySelector("#username").value, password: document.querySelector("#password").value }) });
        const result = await response.json();
        document.querySelector("#status").textContent = result.authenticated ? "Signed in as " + result.username : "Sign-in failed";
        document.querySelector("#status").dataset.authenticated = String(result.authenticated);
      });
    </script>`),
  "/journey-password": page("Synthetic password change", `
    <form>
      <label>Username<input id="username" name="username" autocomplete="username"></label>
      <label>Current password<input id="current" type="password" autocomplete="current-password"></label>
      <label>New password<input id="password" type="password" autocomplete="new-password"></label>
      <button>Change password</button>
    </form><p id="status" role="status"></p>
    <script>
      document.querySelector("form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const response = await fetch("/journey-rotate", { method: "POST", headers: {"content-type":"application/json"}, body: JSON.stringify({ username: document.querySelector("#username").value, password: document.querySelector("#current").value, newPassword: document.querySelector("#password").value }) });
        document.querySelector("#status").textContent = (await response.json()).updated ? "Password changed on this site" : "Password change failed";
      });
    </script>`),
  "/same-frame": page("Same origin frame", `<iframe id="frame" src="/typed"></iframe>`),
  "/cross-frame": page("Cross origin frame", `<iframe id="frame" src="http://127.0.0.1:PORT/typed"></iframe>`),
  "/blank": page("Nothing here", `<p>No login form.</p>`),

  // A sign-in form whose password field a "show password" button turned into a
  // text field. Its name says user, but it holds the password.
  "/toggled": page("Shown password", `
    <form id="login" onsubmit="return false">
      <input type="text" name="uid" id="uid">
      <input type="text" name="user_password" id="pw">
    </form>`),
};

function handle(request, response, accounts) {
  if (request.method === "POST" && ["/journey-auth", "/journey-rotate"].includes(request.url)) {
    let body = "";
    request.on("data", (chunk) => { body += chunk; if (body.length > 8192) request.destroy(); });
    request.on("end", () => {
      let data;
      try { data = JSON.parse(body); } catch { data = {}; }
      const authenticated = typeof data.username === "string" && accounts.get(data.username) === data.password;
      const rotate = request.url === "/journey-rotate";
      const updated = authenticated && typeof data.newPassword === "string" && data.newPassword.length > 0;
      if (rotate && updated) accounts.set(data.username, data.newPassword);
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(rotate ? { updated } : { authenticated, ...(authenticated ? { username: data.username } : {}) }));
    });
    return;
  }
  const { pathname } = new URL(request.url, "http://127.0.0.1");
  const template = PAGES[pathname];
  const body = template && template.replace("127.0.0.1:PORT", `127.0.0.1:${request.headers.host.split(":").pop()}`);
  response.setHeader("content-type", "text/html; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  if (!body) {
    response.statusCode = 404;
    response.end(page("Not found", "<p>Not found.</p>"));
    return;
  }
  response.end(body);
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve(server.address().port));
  });
}

// Listens on 127.0.0.1 and on ::1 with the same port, so that localhost
// reaches it whichever address the browser tries first. Nothing else can reach
// it.
export async function startServer() {
  const accounts = new Map([["rafal@example.com", "Tr0ub4dor&3-never-in-a-reply"]]);
  const serve = (request, response) => handle(request, response, accounts);
  const v4 = http.createServer(serve);
  const port = await listen(v4, 0, "127.0.0.1");
  const v6 = http.createServer(serve);
  try {
    await listen(v6, port, "::1");
  } catch {
    v6.close();
    return { port, close: () => v4.close() };
  }
  return { port, close: () => { v4.close(); v6.close(); } };
}
