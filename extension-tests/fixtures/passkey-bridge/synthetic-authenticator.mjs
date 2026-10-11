// A SYNTHETIC passkey answerer for the extension tests. It is NOT Apassy and
// NOT the vault: it keeps throwaway P-256 keys (in memory or a test file) and answers the wire
// commands passkey_get / passkey_create the way the contract says the app
// will, so that the extension can be checked against an independent verifier
// (@simplewebauthn/server). A pass here says nothing about the real app.
//
// It signs exactly the client_data_json bytes that the extension sent.

import { createHash, createPrivateKey, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import fs from "node:fs";
import { isoCBOR } from "@simplewebauthn/server/helpers";

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

const sha256 = (data) => createHash("sha256").update(data).digest();
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const unb64 = (text) => Buffer.from(text, "base64");

function authData({ rpId, flags, signCount, attested }) {
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(signCount);
  const parts = [sha256(rpId), Buffer.from([flags]), counter];
  if (attested) {
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(attested.credentialId.length);
    parts.push(Buffer.alloc(16), idLength, attested.credentialId, attested.coseKey);
  }
  return Buffer.concat(parts);
}

// file: a JSON file that keeps the throwaway keys between host processes (the
// browser starts one host per request). Test data only.
export function createSyntheticAuthenticator({ file } = {}) {
  const credentials = new Map(); // base64 id -> { rpId, privateKey, userHandle, counter }
  let nextItem = 500;
  if (file && fs.existsSync(file)) {
    for (const [id, c] of Object.entries(JSON.parse(fs.readFileSync(file, "utf8")))) {
      credentials.set(id, { ...c, privateKey: createPrivateKey(c.privateKey) });
    }
  }
  const save = () => {
    if (!file) return;
    const out = {};
    for (const [id, c] of credentials) out[id] = { ...c, privateKey: c.privateKey.export({ format: "pem", type: "pkcs8" }) };
    fs.writeFileSync(file, JSON.stringify(out));
  };

  return {
    credentials,

    create(request) {
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const jwk = publicKey.export({ format: "jwk" });
      const credentialId = randomBytes(16);
      const coseKey = isoCBOR.encode(new Map([
        [1, 2], [3, -7], [-1, 1],
        [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
        [-3, new Uint8Array(Buffer.from(jwk.y, "base64url"))],
      ]));
      const data = authData({
        rpId: request.rp_id,
        flags: FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT,
        signCount: 0,
        attested: { credentialId, coseKey },
      });
      const attestationObject = isoCBOR.encode(new Map([
        ["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(data)],
      ]));
      credentials.set(b64(credentialId), {
        rpId: request.rp_id, privateKey, userHandle: request.user_handle, counter: 0,
      });
      nextItem += 1;
      save();
      return {
        type: "passkey_created",
        rid: request.rid,
        item: nextItem,
        credential_id: b64(credentialId),
        attestation_object: b64(attestationObject),
        authenticator_data: b64(data),
        public_key_spki: b64(publicKey.export({ format: "der", type: "spki" })),
        algorithm: -7,
        client_data_json: request.client_data_json,
      };
    },

    // null when no credential of the RP (the app answers no_match then).
    get(request) {
      const ids = [...credentials.keys()].filter((id) => credentials.get(id).rpId === request.rp_id &&
        (request.allowed.length === 0 || request.allowed.includes(id)));
      if (!ids.length) return null;
      const id = ids[ids.length - 1];
      const credential = credentials.get(id);
      credential.counter += 1;
      save();
      const data = authData({ rpId: request.rp_id, flags: FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS, signCount: credential.counter });
      const signer = createSign("sha256");
      signer.update(Buffer.concat([data, sha256(unb64(request.client_data_json))]));
      return {
        type: "passkey",
        rid: request.rid,
        credential_id: id,
        user_handle: credential.userHandle,
        authenticator_data: b64(data),
        signature: b64(signer.sign(credential.privateKey)),
        client_data_json: request.client_data_json,
      };
    },
  };
}

export const ok = (data) => ({ ok: true, code: "ok", message: "", data });
export const fail = (code) => ({ ok: false, code, message: code, data: { type: "none" } });
