// The page calls navigator.credentials at click time, so the extension's wrapper,
// installed after load, is the one that runs.
const $ = (id) => document.getElementById(id);
const status = (state, text) => { $("status").dataset.state = state; $("status").textContent = text; };

async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const data = await r.json();
  if (!r.ok) { const e = new Error(data.detail || data.error); e.name = `Server:${data.error}`; throw e; }
  return data;
}
const report = (kind, ok, error) => post("/api/client-event", { kind, ok, name: error?.name, message: error?.message }).catch(() => {});

async function ceremony(kind, wrongRp) {
  status("pending", `${kind}…`);
  try {
    if (kind.endsWith("create")) {
      const { ceremonyId, options } = await post("/api/register/options", { wrongRp });
      const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) });
      if (wrongRp) { await report(kind, false, { name: "UnexpectedSuccess", message: "a wrong RP ID was accepted" }); status("error", "DEFECT: wrong RP ID accepted"); return; }
      const result = await post("/api/register/verify", { ceremonyId, credential: credential.toJSON() });
      status("ok", `Created and verified ${result.credentialId}`);
    } else {
      const { ceremonyId, options } = await post("/api/authenticate/options", { wrongRp });
      const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) });
      if (wrongRp) { await report(kind, false, { name: "UnexpectedSuccess", message: "a wrong RP ID was accepted" }); status("error", "DEFECT: wrong RP ID accepted"); return; }
      const result = await post("/api/authenticate/verify", { ceremonyId, credential: credential.toJSON() });
      status("ok", `Signed in and verified ${result.credentialId}`);
    }
  } catch (error) {
    await report(kind, wrongRp, error);
    status(wrongRp ? "refused" : "error", `${kind}: ${error.name}: ${error.message}`);
  }
}
$("create").addEventListener("click", () => ceremony("create", false));
$("get").addEventListener("click", () => ceremony("get", false));
$("wrong-create").addEventListener("click", () => ceremony("wrong_rp_create", true));
$("wrong-get").addEventListener("click", () => ceremony("wrong_rp_get", true));
// Keyboard shortcuts for the driver: a key press is a user activation, and keys do not
// depend on where browser banners move the buttons.
document.addEventListener("keydown", (event) => {
  if (event.isComposing || event.repeat) return;
  const run = { c: ["create", false], g: ["get", false], w: ["wrong_rp_create", true], x: ["wrong_rp_get", true] }[event.key];
  if (run) ceremony(...run);
});
