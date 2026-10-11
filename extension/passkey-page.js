// The page part of the passkey bridge. It runs in the MAIN world of the top
// frame, at document_start, and only after the owner turned on passkeys in the
// popup (background.js registers it).
//
// It wraps navigator.credentials.create and .get for publicKey requests. It
// sends the options to passkey-bridge.js (ISOLATED world) as JSON with base64url
// bytes, and builds a PublicKeyCredential from the answer. This script is as
// untrusted as the page: the service worker takes the origin from the browser,
// checks the RP ID, and builds clientDataJSON. A page that calls the bridge
// itself gets nothing that WebAuthn would not give it.
//
// When Apassy cannot serve a request before any owner check (an option it does
// not support, the app not running, a locked vault, no passkey for the site),
// the original browser method runs. After the owner check started, a failure is
// a DOMException and never a second try.

(() => {
  "use strict";

  if (window.top !== window) return;

  const Container = window.CredentialsContainer;
  const PublicKey = window.PublicKeyCredential;
  const Attestation = window.AuthenticatorAttestationResponse;
  const Assertion = window.AuthenticatorAssertionResponse;
  if (typeof Container !== "function" || typeof PublicKey !== "function" ||
      typeof Attestation !== "function" || typeof Assertion !== "function") return;

  const REQUEST = "apassy-passkey-request";
  const RESPONSE = "apassy-passkey-response";
  // The bridge answers "ack" at once. Without it, the browser does the request.
  const ACK_MS = 1500;
  // The service worker ends each request after at most 180 s.
  const LIMIT_MS = 200 * 1000;
  const MAX_DETAIL = 64 * 1024;

  // The page may change built-ins after it loads. Keep the ones used here.
  const nativeCreate = Container.prototype.create;
  const nativeGet = Container.prototype.get;
  const apply = Reflect.apply;
  const defineProperty = Object.defineProperty;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const objectCreate = Object.create;
  const objectKeys = Object.keys;
  const isArray = Array.isArray;
  const isView = ArrayBuffer.isView;
  const Bytes = Uint8Array;
  const Buffer = ArrayBuffer;
  const Signal = window.AbortSignal;
  const Event = window.CustomEvent;
  const Exception = window.DOMException;
  const stringify = JSON.stringify;
  const parse = JSON.parse;
  const dispatch = EventTarget.prototype.dispatchEvent;
  const listen = EventTarget.prototype.addEventListener;
  const unlisten = EventTarget.prototype.removeEventListener;
  const fromCharCode = String.fromCharCode;
  const encode64 = window.btoa;
  const decode64 = window.atob;
  const later = window.setTimeout;
  const cancelLater = window.clearTimeout;
  const uuid = window.crypto.randomUUID.bind(window.crypto);

  const pending = new Map();

  class Unsupported extends Error {}
  const unsupported = () => { throw new Unsupported(); };

  // --- bytes -----------------------------------------------------------------

  // A copy of a BufferSource. Anything else (also a shared buffer) is left to
  // the browser, which throws the right TypeError.
  function bytesOf(value) {
    if (value instanceof Buffer) return new Bytes(value.slice(0));
    if (isView(value) && value.buffer instanceof Buffer) {
      return new Bytes(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    return unsupported();
  }

  function base64url(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += apply(fromCharCode, null, bytes.subarray(i, i + 0x8000));
    }
    return encode64(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // base64url text to a new ArrayBuffer. Throws on anything else.
  function bufferOf(text, min, max) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
      throw new TypeError("bad bytes");
    }
    const binary = decode64(text.replace(/-/g, "+").replace(/_/g, "/"));
    if (binary.length < min || binary.length > max) throw new TypeError("bad length");
    const bytes = new Bytes(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    if (base64url(bytes) !== text) throw new TypeError("not canonical");
    return bytes.buffer;
  }

  const copy = (buffer) => buffer.slice(0);

  // --- options to JSON ---------------------------------------------------------

  // WebIDL DOMString conversion. A missing required member is left to the
  // browser.
  function string(value) {
    if (value === undefined) return unsupported();
    return `${value}`;
  }

  // A sequence. Without a default, the member is required.
  function list(value, empty) {
    if (value === undefined) return empty === undefined ? unsupported() : empty;
    return isArray(value) ? value : unsupported();
  }

  function descriptor(item) {
    if (item === null || typeof item !== "object") return unsupported();
    return { type: string(item.type), id: base64url(bytesOf(item.id)) };
  }

  // Only credProps is supported (create). Any other extension, also an unknown
  // one, goes to the browser: no made-up output for prf, largeBlob, or appid.
  function extensionsOf(value, allowed) {
    if (value === undefined) return undefined;
    if (value === null || typeof value !== "object") return unsupported();
    const out = {};
    for (const key of objectKeys(value)) {
      if (value[key] === undefined) continue;
      // A default that the browser's JSON parser fills in; it asks for nothing.
      if (key === "enforceCredentialProtectionPolicy" && value[key] === false) continue;
      if (!allowed.includes(key)) return unsupported();
      out[key] = Boolean(value[key]);
    }
    return out;
  }

  function creationJSON(pk) {
    if (pk === null || typeof pk !== "object") return unsupported();
    const { rp, user } = pk;
    if (rp === null || typeof rp !== "object" || user === null || typeof user !== "object") return unsupported();
    const out = {
      rp: { name: string(rp.name) },
      user: { id: base64url(bytesOf(user.id)), name: string(user.name), displayName: string(user.displayName) },
      challenge: base64url(bytesOf(pk.challenge)),
      pubKeyCredParams: list(pk.pubKeyCredParams).map((param) => {
        if (param === null || typeof param !== "object") return unsupported();
        return { type: string(param.type), alg: Number(param.alg) };
      }),
      excludeCredentials: list(pk.excludeCredentials, []).map(descriptor),
    };
    if (rp.id !== undefined) out.rp.id = string(rp.id);
    if (pk.timeout !== undefined) out.timeout = Number(pk.timeout);
    const selection = pk.authenticatorSelection;
    if (selection !== undefined) {
      if (selection === null || typeof selection !== "object") return unsupported();
      out.authenticatorSelection = {};
      for (const key of ["authenticatorAttachment", "residentKey", "userVerification"]) {
        if (selection[key] !== undefined) out.authenticatorSelection[key] = string(selection[key]);
      }
      if (selection.requireResidentKey !== undefined) {
        out.authenticatorSelection.requireResidentKey = Boolean(selection.requireResidentKey);
      }
    }
    if (pk.attestation !== undefined) out.attestation = string(pk.attestation);
    // Attestation formats ask for an attestation that Apassy does not make.
    // The browser's JSON parser fills in the default, an empty list.
    if (list(pk.attestationFormats, []).length) return unsupported();
    if (pk.hints !== undefined) out.hints = list(pk.hints).map(string);
    const extensions = extensionsOf(pk.extensions, ["credProps"]);
    if (extensions) out.extensions = extensions;
    return out;
  }

  function requestJSON(pk) {
    if (pk === null || typeof pk !== "object") return unsupported();
    const out = {
      challenge: base64url(bytesOf(pk.challenge)),
      allowCredentials: list(pk.allowCredentials, []).map(descriptor),
    };
    if (pk.rpId !== undefined) out.rpId = string(pk.rpId);
    if (pk.timeout !== undefined) out.timeout = Number(pk.timeout);
    if (pk.userVerification !== undefined) out.userVerification = string(pk.userVerification);
    if (pk.hints !== undefined) out.hints = list(pk.hints).map(string);
    const extensions = extensionsOf(pk.extensions, []);
    if (extensions) out.extensions = extensions;
    return out;
  }

  const OUTER = ["publicKey", "signal", "mediation"];

  // The JSON of a request that Apassy may serve, or null for the browser.
  function requestFor(op, options) {
    try {
      if (options === null || typeof options !== "object" || options.publicKey === undefined) return null;
      // Another credential type in the same call (password, identity, otp).
      for (const key of objectKeys(options)) {
        if (!OUTER.includes(key) && options[key] !== undefined) return null;
      }
      // Conditional (autofill) and immediate requests stay with the browser.
      const mediation = options.mediation;
      if (mediation !== undefined && mediation !== "optional" && mediation !== "required") return null;
      const signal = options.signal;
      if (signal !== undefined && signal !== null && !(signal instanceof Signal)) return null;
      if (signal && signal.aborted) return null;
      const json = op === "create" ? creationJSON(options.publicKey) : requestJSON(options.publicKey);
      const message = { op, options: json };
      if (mediation !== undefined) message.mediation = mediation;
      return message;
    } catch (_) {
      // Unsupported, or a value that the browser rejects with its own error.
      return null;
    }
  }

  // --- the answer ------------------------------------------------------------

  function own(target, values) {
    for (const key of objectKeys(values)) {
      defineProperty(target, key, { value: values[key], enumerable: true, configurable: true, writable: false });
    }
  }

  function method(target, name, body) {
    const holder = { [name]() { return body(); } };
    defineProperty(target, name, { value: holder[name], enumerable: true, configurable: true, writable: true });
  }

  // Only {} or {credProps: {rk: true}}.
  function extensionResults(op, value) {
    if (value === null || typeof value !== "object") throw new TypeError("bad results");
    const keys = objectKeys(value);
    if (keys.length === 0) return () => ({});
    if (op === "create" && keys.length === 1 && keys[0] === "credProps" &&
        value.credProps && objectKeys(value.credProps).length === 1 && value.credProps.rk === true) {
      return () => ({ credProps: { rk: true } });
    }
    throw new TypeError("bad results");
  }

  const TRANSPORTS = ["internal", "hybrid"];

  // A PublicKeyCredential: instanceof and the prototype chain hold, the
  // attributes are own properties, and toJSON gives the base64url JSON of
  // WebAuthn level 3.
  function credentialFrom(op, c) {
    if (c === null || typeof c !== "object") throw new TypeError("bad credential");
    const rawId = bufferOf(c.id, 1, 1023);
    const id = c.id;
    const clientDataJSON = bufferOf(c.clientDataJSON, 1, 4096);
    const results = extensionResults(op, c.clientExtensionResults);
    let response;
    let responseJSON;
    if (op === "create") {
      const attestationObject = bufferOf(c.attestationObject, 1, 16384);
      const authenticatorData = bufferOf(c.authenticatorData, 37, 16384);
      const publicKey = bufferOf(c.publicKey, 1, 1024);
      const algorithm = c.publicKeyAlgorithm;
      if (!Number.isInteger(algorithm)) throw new TypeError("bad algorithm");
      const transports = isArray(c.transports) ? c.transports.filter((t) => TRANSPORTS.includes(t)) : ["internal"];
      response = objectCreate(Attestation.prototype);
      own(response, { clientDataJSON, attestationObject });
      method(response, "getAuthenticatorData", () => copy(authenticatorData));
      method(response, "getPublicKey", () => copy(publicKey));
      method(response, "getPublicKeyAlgorithm", () => algorithm);
      method(response, "getTransports", () => transports.slice());
      responseJSON = () => ({
        clientDataJSON: c.clientDataJSON,
        authenticatorData: c.authenticatorData,
        transports: transports.slice(),
        publicKey: c.publicKey,
        publicKeyAlgorithm: algorithm,
        attestationObject: c.attestationObject,
      });
    } else {
      const authenticatorData = bufferOf(c.authenticatorData, 37, 16384);
      const signature = bufferOf(c.signature, 1, 1024);
      const userHandle = c.userHandle === null ? null : bufferOf(c.userHandle, 1, 64);
      response = objectCreate(Assertion.prototype);
      own(response, { clientDataJSON, authenticatorData, signature, userHandle });
      responseJSON = () => {
        const out = {
          clientDataJSON: c.clientDataJSON,
          authenticatorData: c.authenticatorData,
          signature: c.signature,
        };
        if (userHandle) out.userHandle = c.userHandle;
        return out;
      };
    }
    const credential = objectCreate(PublicKey.prototype);
    own(credential, { id, rawId, type: "public-key", response, authenticatorAttachment: "platform" });
    method(credential, "getClientExtensionResults", results);
    method(credential, "toJSON", () => ({
      id,
      rawId: id,
      response: responseJSON(),
      authenticatorAttachment: "platform",
      clientExtensionResults: results(),
      type: "public-key",
    }));
    return credential;
  }

  const ERRORS = {
    NotAllowedError: "The operation either timed out or was not allowed.",
    InvalidStateError: "The authenticator already holds one of the excluded credentials.",
    AbortError: "The operation was aborted.",
  };

  function errorFrom(name) {
    const known = Object.prototype.hasOwnProperty.call(ERRORS, name) ? name : "NotAllowedError";
    return new Exception(ERRORS[known], known);
  }

  // --- the channel -------------------------------------------------------------

  function send(message) {
    apply(dispatch, window, [new Event(REQUEST, { detail: stringify(message) })]);
  }

  apply(listen, window, [RESPONSE, (event) => {
    const detail = event.detail;
    if (typeof detail !== "string" || detail.length > MAX_DETAIL) return;
    let message;
    try {
      message = parse(detail);
    } catch (_) {
      return;
    }
    if (!message || typeof message.rid !== "string") return;
    const handle = pending.get(message.rid);
    if (handle) handle(message);
  }]);

  function call(op, native, container, args) {
    const browser = () => apply(native, container, args);
    if (!(container instanceof Container)) return browser();
    const options = args[0];
    const request = requestFor(op, options);
    if (!request) return browser();
    const signal = options.signal || null;

    return new Promise((resolve, reject) => {
      const rid = uuid();
      let acked = false;
      let done = false;
      let ackTimer = null;
      let limitTimer = null;
      const end = () => {
        done = true;
        pending.delete(rid);
        cancelLater(ackTimer);
        cancelLater(limitTimer);
        if (signal) apply(unlisten, signal, ["abort", onAbort]);
      };
      const toBrowser = () => {
        try {
          resolve(browser());
        } catch (error) {
          reject(error);
        }
      };
      const onAbort = () => {
        if (done) return;
        end();
        send({ rid, op: "cancel" });
        reject(signal.reason !== undefined ? signal.reason : errorFrom("AbortError"));
      };
      pending.set(rid, (answer) => {
        if (done) return;
        if (answer.kind === "ack") {
          acked = true;
          return;
        }
        end();
        if (answer.kind === "fallback") {
          toBrowser();
        } else if (answer.kind === "result" && answer.op === op) {
          try {
            resolve(credentialFrom(op, answer.credential));
          } catch (_) {
            reject(errorFrom("NotAllowedError"));
          }
        } else {
          reject(errorFrom(answer.kind === "error" ? answer.name : "NotAllowedError"));
        }
      });
      ackTimer = later(() => {
        if (acked || done) return;
        end();
        send({ rid, op: "cancel" });
        toBrowser();
      }, ACK_MS);
      limitTimer = later(() => {
        if (done) return;
        end();
        send({ rid, op: "cancel" });
        reject(errorFrom("NotAllowedError"));
      }, LIMIT_MS);
      if (signal) apply(listen, signal, ["abort", onAbort]);
      send({ rid, ...request });
    });
  }

  // The wrappers keep the name, the length, and the property flags of the
  // originals.
  function install(name, native) {
    const holder = { [name](options) { return call(name, native, this, arguments); } };
    const wrapper = holder[name];
    defineProperty(wrapper, "length", { value: native.length });
    const flags = getOwnPropertyDescriptor(Container.prototype, name) ||
      { writable: true, enumerable: true, configurable: true };
    defineProperty(Container.prototype, name, {
      value: wrapper, writable: flags.writable, enumerable: flags.enumerable, configurable: flags.configurable,
    });
  }

  install("create", nativeCreate);
  install("get", nativeGet);
})();
