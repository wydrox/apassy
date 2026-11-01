// Synthetic pages shared by the CDP smoke and CI Playwright specifications.
export function savePage(pathname) {
  const kind = pathname.split("/").pop();
  const done = kind === "done";
  const first = kind === "step1", second = kind === "step2";
  const signup = kind === "signup", change = kind === "change";
  const xhr = ["xhr", "change", "click"].includes(kind);
  const title = done ? "You are signed in" : first ? "Sign in: your username" : signup ? "Create an account" : change ? "Change password" : "Sign in";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><title>${title}</title><style>
    body{font:15px/1.5 system-ui;margin:160px auto;max-width:380px;background:light-dark(#f6f6f7,#19191b);color:light-dark(#242426,#f5f5f7)}h1{font-size:24px}input{font:inherit;display:block;box-sizing:border-box;width:100%;height:40px;margin:6px 0 18px;border:1px solid #85858e;border-radius:6px;padding:8px}button{font:inherit;padding:9px 14px;border:1px solid #85858e;border-radius:7px}form[hidden]{display:none}
    </style></head><body><h1>${title}</h1>${done ? '<p>The synthetic website accepted the submission.</p>' : `<form action="/offer/done" method="post">
    ${second ? "" : '<label>Username<input id="username" autocomplete="username" type="email" required></label>'}
    ${change ? '<label>Current password<input id="current" type="password" autocomplete="current-password"></label>' : ""}
    ${first ? "" : `<label>${change ? "New password" : "Password"}<input id="password" type="password" autocomplete="${signup || change ? "new-password" : "current-password"}" required></label>`}
    ${signup || change ? '<label>Repeat password<input id="confirm" type="password" autocomplete="new-password" required></label>' : ""}
    <button id="submit" type="${kind === "click" ? "button" : "submit"}">${first ? "Next" : signup ? "Create account" : change ? "Change password" : "Sign in"}</button></form><p id="status" role="status"></p>
    <script>
    ${first ? 'document.querySelector("form").onsubmit=e=>{e.preventDefault();location.href="/offer/step2";};' : ""}
    ${xhr ? `document.querySelector("${kind === "click" ? "#submit" : "form"}").addEventListener("${kind === "click" ? "click" : "submit"}",async e=>{e.preventDefault();await fetch("/offer/done");document.querySelector("form").hidden=true;document.querySelector("#status").textContent="${change ? "Password changed" : "Signed in"}";});` : ""}
    </script>`}</body></html>`;
}
