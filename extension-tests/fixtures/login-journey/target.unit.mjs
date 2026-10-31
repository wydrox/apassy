// A small synthetic DOM for exact-node targeting. This is not browser acceptance.
import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
const source = fs.readFileSync(new URL("../../../extension/login-target.js", import.meta.url), "utf8");
class Node {
  constructor(tag = "DIV") { this.tagName = tag; this.children = []; this.isConnected = true; }
  append(...els) { for (const el of els) { el.parent = this; el.parentElement = this.tagName === "DOCUMENT" || this.tagName === "SHADOWROOT" ? null : this; this.children.push(el); } }
  querySelectorAll(selector = "*") {
    const all = this.children.flatMap((el) => [el, ...el.querySelectorAll()]);
    return selector === "*" ? all : all.filter((el) => selector.split(",").some((part) => {
      const match = part.trim().match(/^(button|input)(?:\[type=(\w+)\])?$/i);
      return match && el.tagName === match[1].toUpperCase() && (!match[2] || el.type === match[2]);
    }));
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  getAttribute(name) { return this[name] ?? null; }
  hasAttribute(name) { return this[name] !== undefined; }
  closest() { return null; }
  getRootNode() { return this.parent ? this.parent.getRootNode() : this; }
}
class Input extends Node {
  constructor(name, type = "text", autocomplete = "") { super("INPUT"); Object.assign(this, { name, type, autocomplete, id: name, disabled: false, readOnly: false, placeholder: "", _value: "", form: null }); }
  get value() { return this._value; } set value(v) { this._value = v; }
  getBoundingClientRect() { return { width: 200, height: 32 }; }
  getAttribute(name) { return this[name] || ""; }
  checkVisibility() { return true; }
  focus() {}
  dispatchEvent(event) { this.onEvent?.(event); }
}
function setup({ two = false, shadow = false, firstOnly = false } = {}) {
  const document = new Node("DOCUMENT"); document.activeElement = null;
  const form = new Node("FORM"); form.action = "https://example.com/signin";
  const username = new Input("username", "email", "username");
  const password = new Input("password", "password", "current-password");
  username.form = form; password.form = form; form.append(username, ...(firstOnly ? [] : [password]));
  if (shadow) {
    const host = new Node("LOGIN-BOX"); host.shadowRoot = new Node("SHADOWROOT");
    host.shadowRoot.activeElement = username; host.shadowRoot.append(form); document.append(host); document.activeElement = host;
  } else { document.append(form); document.activeElement = username; }
  let other;
  if (two) {
    const form2 = new Node("FORM"); form2.action = form.action;
    const user2 = new Input("other-user", "email", "username");
    const pass2 = new Input("other-password", "password", "current-password");
    user2.form = pass2.form = form2; form2.append(user2, pass2); document.append(form2); other = { form: form2, username: user2, password: pass2 };
  }
  const location = { origin: "https://example.com", href: "https://example.com/login" };
  document.baseURI = location.href;
  const context = vm.createContext({ document, location, origin: location.origin, HTMLInputElement: Input, crypto: webcrypto, URL, Date, Event: class { constructor(type) { this.type = type; } } });
  context.self = context; vm.runInContext(source, context);
  return { api: context.apassyLoginTarget, document, form, username, password, location, other };
}

test("focused second form receives both values; unrelated form stays empty", () => {
  const s = setup({ two: true }); s.document.activeElement = s.other.username;
  const target = s.api.capture();
  const result = s.api.fill(target.token, s.location.origin, "second@example.com", "synthetic-secret");
  assert.equal(result.password, true); assert.equal(s.other.username.value, "second@example.com");
  assert.equal(s.other.password.value, "synthetic-secret"); assert.equal(s.password.value, ""); assert.equal(s.username.value, "");
});

test("toolbar capture refuses ambiguity when no login field is focused", () => {
  const s = setup({ two: true }); s.document.activeElement = new Node("BODY");
  assert.equal(s.api.capture().reason, "ambiguous");
});

test("same-document form replacement is rejected before any fill", () => {
  const s = setup(); const target = s.api.capture();
  const replacement = new Input("password", "password", "current-password"); replacement.form = s.form;
  s.password.isConnected = false; s.form.children[1] = replacement;
  const result = s.api.fill(target.token, s.location.origin, "user", "secret");
  assert.equal(result.ok, false); assert.equal(replacement.value, ""); assert.equal(s.username.value, "");
});

test("SPA URL change, action change, focus to another form each invalidate target", () => {
  for (const change of [(s) => { s.location.href += "?next=changed"; }, (s) => { s.form.action += "?changed"; }, (s) => { s.document.activeElement = s.other.username; }]) {
    const s = setup({ two: true }); const target = s.api.capture(); change(s);
    assert.equal(s.api.fill(target.token, s.location.origin, "user", "secret").ok, false);
    assert.equal(s.password.value, ""); assert.equal(s.other.password.value, "");
  }
});

test("open shadow root has an independently captured form and fields", () => {
  const s = setup({ shadow: true }); const target = s.api.capture();
  assert.equal(target.ok, true); assert.equal(s.api.fill(target.token, s.location.origin, "shadow", "secret").ok, true);
  assert.equal(s.username.value, "shadow"); assert.equal(s.password.value, "secret");
});

test("username-first result says no password filled", () => {
  const s = setup({ firstOnly: true }); const target = s.api.capture();
  const result = s.api.fill(target.token, s.location.origin, "step-one", "secret");
  assert.equal(result.username, true); assert.equal(result.password, false); assert.equal(s.username.value, "step-one");
});

test("a password-masked OTP is excluded when capturing its username form", () => {
  const s = setup(); s.password.autocomplete = "one-time-code";
  assert.equal(s.api.eligible(s.password), false);
  const target = s.api.capture(s.username);
  assert.equal(target.passwordFields, 0);
  assert.equal(target.newPasswordFields, 0);
  const result = s.api.fill(target.token, s.location.origin, "step-one", "synthetic-secret");
  assert.equal(result.username, true);
  assert.equal(result.password, false);
  assert.equal(s.password.value, "");
});

test("synchronous page replacement after username input cannot redirect password", () => {
  const s = setup(); const target = s.api.capture();
  let replacement;
  s.username.onEvent = (e) => {
    if (e.type !== "input") return;
    replacement = new Input("password", "password", "current-password"); replacement.form = s.form;
    s.password.isConnected = false; s.form.children[1] = replacement;
  };
  const result = s.api.fill(target.token, s.location.origin, "user", "secret");
  assert.equal(result.ok, false); assert.equal(result.reason, "target"); assert.equal(replacement.value, "");
});

test("capture uses preferred originating field while the chooser has focus", () => {
  const s = setup({ two: true }); s.document.activeElement = new Node("DIV");
  const target = s.api.capture(s.other.username); assert.equal(target.ok, true);
  s.api.fill(target.token, s.location.origin, "second", "secret");
  assert.equal(s.other.password.value, "secret"); assert.equal(s.password.value, "");
});

test("update chooses new-password with matching confirmation when username or submit has focus", () => {
  for (const focusSubmit of [false, true]) {
    const s = setup(); s.password.value = "old-password";
    const next = new Input("next", "password", "new-password"); next.form = s.form; next.value = "new-password";
    const confirm = new Input("confirm", "password", "new-password"); confirm.form = s.form; confirm.value = next.value;
    s.form.append(next, confirm);
    if (focusSubmit) s.document.activeElement = new Node("BUTTON");
    const target = s.api.capture();
    assert.equal(s.api.read(target.token, true, "update").password, "new-password");
    confirm.value = "different";
    assert.equal(s.api.read(target.token, true, "update").reason, "password_confirmation");
  }
});

test("update rejects multiple unmarked passwords rather than storing the old one", () => {
  const s = setup(); s.password.autocomplete = ""; s.password.value = "old-password";
  const next = new Input("next", "password", ""); next.form = s.form; next.value = "new-password"; s.form.append(next);
  const target = s.api.capture();
  assert.equal(s.api.read(target.token, true, "update").reason, "ambiguous_password");
});
