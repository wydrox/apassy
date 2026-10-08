// The web pages of the store screenshots. make-assets.mjs serves them on their
// https addresses through a Playwright route, so nothing goes to the network
// and the extension sees a real https page of that site. Synthetic sites only:
// GitHub, as on the website, and two made-up sites on example.com.

const page = (title, css, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<meta name="color-scheme" content="light">
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; color: #1f2328; }
  label { display: block; font-weight: 600; margin: 0 0 6px; }
  input {
    display: block; width: 100%; height: 34px; margin: 0 0 14px; padding: 5px 10px; font: inherit;
    border: 1px solid #d1d9e0; border-radius: 6px; background: #ffffff; color: #1f2328;
  }
  button { display: block; width: 100%; height: 34px; border: 0; border-radius: 6px; font: inherit; font-weight: 600; color: #ffffff; }
  ${css}
</style></head>
<body>${body}</body></html>`;

// A GitHub-like sign-in page. The column sits on the left: the popup covers
// the right side of the screenshot.
const GITHUB_LOGIN = page("Sign in to GitHub", `
  body { background: #ffffff; }
  .col { width: 300px; margin-left: 64px; padding-top: 28px; }
  .logo { width: 44px; height: 44px; margin: 0 auto 14px; border-radius: 50%; background: #1f2328; }
  h1 { margin: 0 0 16px; font-size: 22px; font-weight: 300; text-align: center; letter-spacing: -0.2px; }
  .box { padding: 16px; border: 1px solid #d1d9e0; border-radius: 6px; background: #f6f8fa; }
  button { background: #1f883d; }
  .new { margin-top: 14px; padding: 14px; border: 1px solid #d1d9e0; border-radius: 6px; text-align: center; }
  .new a { color: #0969da; text-decoration: none; }`, `
  <div class="col">
    <div class="logo"></div>
    <h1>Sign in to GitHub</h1>
    <form class="box" onsubmit="return false">
      <label for="username">Username or email address</label>
      <input type="text" id="username" name="login" autocomplete="username">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
    <p class="new">New to GitHub? <a href="#">Create an account</a></p>
  </div>`);

// A made-up notes site where the owner types a login by hand.
const NOTES_LOGIN = page("Sign in · Fieldnotes", `
  body { background: #f4f1ea; }
  .col { width: 300px; margin-left: 64px; padding-top: 30px; }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; font-size: 18px; font-weight: 700; color: #2e3b2f; }
  .leaf { width: 30px; height: 30px; border-radius: 9px 2px 9px 2px; background: #3f7d4e; }
  .card { padding: 20px; border-radius: 12px; background: #ffffff; box-shadow: 0 1px 2px rgba(0,0,0,.06), 0 8px 24px rgba(46,59,47,.08); }
  h1 { margin: 0 0 14px; font-size: 18px; }
  input { border-color: #d9d4c7; }
  button { background: #3f7d4e; }`, `
  <div class="col">
    <div class="brand"><span class="leaf"></span>Fieldnotes</div>
    <form class="card" onsubmit="return false">
      <h1>Welcome back</h1>
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="username">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div>`);

// A made-up shop with a sign-up form: one new password field.
const SHOP_SIGNUP = page("Create your account · Corner Shop", `
  body { background: #fbf7f4; }
  .col { width: 300px; margin-left: 64px; padding-top: 30px; }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; font-size: 18px; font-weight: 700; color: #4a2a1d; }
  .bag { width: 30px; height: 30px; border-radius: 8px; background: #d9572b; }
  .card { padding: 20px; border-radius: 12px; background: #ffffff; box-shadow: 0 1px 2px rgba(0,0,0,.06), 0 8px 24px rgba(74,42,29,.08); }
  h1 { margin: 0 0 14px; font-size: 18px; }
  input { border-color: #e6d9d0; }
  button { background: #d9572b; }`, `
  <div class="col">
    <div class="brand"><span class="bag"></span>Corner Shop</div>
    <form class="card" onsubmit="return false">
      <h1>Create your account</h1>
      <label for="email">Email</label>
      <input type="email" id="email" name="email" autocomplete="email">
      <label for="new-password">Password</label>
      <input type="password" id="new-password" name="password" autocomplete="new-password">
      <button type="submit">Create account</button>
    </form>
  </div>`);

export const STORE_PAGES = {
  "https://github.com/login": GITHUB_LOGIN,
  "https://notes.example.com/login": NOTES_LOGIN,
  "https://shop.example.com/signup": SHOP_SIGNUP,
};

// What the mock app holds: two logins for github.com.
export const STORE_LOGINS = [
  { item: 1, title: "GitHub", username: "rafal", password: "synthetic-not-a-password-1", site: "github.com" },
  { item: 2, title: "Work GitHub", username: "rafal-work", password: "synthetic-not-a-password-2", site: "github.com" },
];
