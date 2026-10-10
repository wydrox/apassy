// Page logic for the passkey test relying party.
//
// The page calls navigator.credentials at click time and looks up every
// helper then too, so an extension that replaces them after load still works.
// Add ?transform=manual to skip the native JSON helpers and use the base64url
// code below. Add ?allow=list to sign in with an allowCredentials list.

const params = new URLSearchParams(location.search);
const forceManual = params.get("transform") === "manual";
const useAllowList = params.get("allow") === "list";

const $ = (id) => document.getElementById(id);
const createButton = $("create-passkey");
const signInButton = $("sign-in");

function toBase64url(value) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function setStatus(state, text, extra = {}) {
  const status = $("status");
  status.dataset.state = state;
  status.textContent = text;
  for (const key of ["errorName", "credentialId"]) delete status.dataset[key];
  Object.assign(status.dataset, extra);
}

function setBusy(busy) {
  createButton.disabled = busy;
  signInButton.disabled = busy;
}

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.detail || data.error || `HTTP ${response.status}`);
    error.name = "ServerRejected";
    throw error;
  }
  return data;
}

function note(via) {
  const el = $("transform");
  el.dataset.transform = via;
  el.textContent = `JSON transform: ${via}`;
}

function nativeParse(name) {
  return !forceManual && typeof PublicKeyCredential !== "undefined" && typeof PublicKeyCredential[name] === "function";
}

function creationOptions(json) {
  if (nativeParse("parseCreationOptionsFromJSON")) {
    note("native");
    return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  }
  note("manual");
  return {
    ...json,
    challenge: fromBase64url(json.challenge),
    user: { ...json.user, id: fromBase64url(json.user.id) },
    excludeCredentials: (json.excludeCredentials ?? []).map((c) => ({ ...c, id: fromBase64url(c.id) })),
  };
}

function requestOptions(json) {
  if (nativeParse("parseRequestOptionsFromJSON")) {
    note("native");
    return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  }
  note("manual");
  return {
    ...json,
    challenge: fromBase64url(json.challenge),
    allowCredentials: (json.allowCredentials ?? []).map((c) => ({ ...c, id: fromBase64url(c.id) })),
  };
}

function credentialToJSON(credential) {
  if (!forceManual && typeof credential.toJSON === "function") return credential.toJSON();
  const out = {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
  };
  if (credential.authenticatorAttachment) out.authenticatorAttachment = credential.authenticatorAttachment;
  const r = credential.response;
  if (r.attestationObject) {
    out.response = {
      clientDataJSON: toBase64url(r.clientDataJSON),
      attestationObject: toBase64url(r.attestationObject),
    };
    const transports = r.getTransports?.();
    if (transports) out.response.transports = transports;
    const authData = r.getAuthenticatorData?.();
    if (authData) out.response.authenticatorData = toBase64url(authData);
    const publicKey = r.getPublicKey?.();
    if (publicKey) out.response.publicKey = toBase64url(publicKey);
    const algorithm = r.getPublicKeyAlgorithm?.();
    if (algorithm !== undefined && algorithm !== null) out.response.publicKeyAlgorithm = algorithm;
  } else {
    out.response = {
      clientDataJSON: toBase64url(r.clientDataJSON),
      authenticatorData: toBase64url(r.authenticatorData),
      signature: toBase64url(r.signature),
    };
    if (r.userHandle && r.userHandle.byteLength > 0) out.response.userHandle = toBase64url(r.userHandle);
  }
  return out;
}

async function refreshInfo() {
  const info = await (await fetch("/api/status")).json();
  $("rp-origin").textContent = info.origin;
  $("rp-id").textContent = info.rpID;
  $("rp-count").textContent = String(info.credentialCount);
}

function describeFailure(error) {
  if (error.name === "InvalidStateError") return "This passkey already exists for the account (excluded).";
  if (error.name === "NotAllowedError") return "The passkey request was cancelled or refused.";
  return `${error.name}: ${error.message}`;
}

async function run(label, ceremony) {
  setBusy(true);
  setStatus("pending", `${label}…`);
  try {
    await ceremony();
  } catch (error) {
    setStatus("error", `${label} failed. ${describeFailure(error)}`, { errorName: error.name });
  } finally {
    setBusy(false);
    refreshInfo().catch(() => {});
  }
}

createButton.addEventListener("click", () =>
  run("Create passkey", async () => {
    const { ceremonyId, options } = await post("/api/register/options", {});
    const credential = await navigator.credentials.create({ publicKey: creationOptions(options) });
    if (!credential) throw new Error("No credential returned");
    const result = await post("/api/register/verify", { ceremonyId, credential: credentialToJSON(credential) });
    setStatus("registered", "Passkey created. The server verified it.", { credentialId: result.credentialId });
  }),
);

signInButton.addEventListener("click", () =>
  run("Sign in", async () => {
    const { ceremonyId, options } = await post("/api/authenticate/options", { discoverable: !useAllowList });
    const credential = await navigator.credentials.get({ publicKey: requestOptions(options) });
    if (!credential) throw new Error("No credential returned");
    const result = await post("/api/authenticate/verify", { ceremonyId, credential: credentialToJSON(credential) });
    setStatus("signed-in", "Signed in. The server verified the passkey.", { credentialId: result.credentialId });
  }),
);

refreshInfo().catch((error) => setStatus("error", `Cannot reach the server: ${error.message}`));
