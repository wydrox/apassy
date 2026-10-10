// Software WebAuthn authenticator for the RP unit checks.
//
// It only SIGNS: it builds the JSON that a browser would send. It never
// verifies anything. All checking is done by @simplewebauthn/server inside the
// RP. It is not the Apassy authenticator and shares no code with it.
// Each override breaks one thing on purpose, for the negative checks.

import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const unb64u = (text) => new Uint8Array(Buffer.from(text, "base64url"));
const sha256 = (data) => createHash("sha256").update(data).digest();

function authData({ rpID, flags, signCount, attested }) {
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(signCount);
  const parts = [sha256(rpID), Buffer.from([flags]), counter];
  if (attested) {
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(attested.credentialId.length);
    parts.push(attested.aaguid, idLength, attested.credentialId, attested.coseKey);
  }
  return Buffer.concat(parts);
}

function clientData({ type, challenge, origin }) {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

export function createTestAuthenticator({ aaguid = Buffer.alloc(16, 0xa5), backedUp = false } = {}) {
  const credentials = new Map(); // base64url id -> { privateKey, userHandle }

  return {
    credentialIds: () => [...credentials.keys()],

    // `options` is the optionsJSON from POST /api/register/options.
    register(options, { origin, overrides = {} }) {
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const jwk = publicKey.export({ format: "jwk" });
      const credentialId = overrides.credentialId ?? randomBytes(32);
      const coseKey = isoCBOR.encode(
        new Map([
          [1, 2], // kty: EC2
          [3, -7], // alg: ES256
          [-1, 1], // crv: P-256
          [-2, unb64u(jwk.x)],
          [-3, unb64u(jwk.y)],
        ]),
      );
      const flags =
        overrides.flags ??
        (FLAG_UP | FLAG_UV | FLAG_AT | (backedUp ? FLAG_BE | FLAG_BS : FLAG_BE));
      const data = authData({
        rpID: overrides.rpID ?? options.rp.id,
        flags,
        signCount: overrides.signCount ?? 0,
        attested: { aaguid, credentialId, coseKey },
      });
      const attestationObject = isoCBOR.encode(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", data]]));
      const id = b64u(credentialId);
      credentials.set(id, { privateKey, userHandle: options.user.id });
      return {
        id,
        rawId: id,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          clientDataJSON: b64u(
            clientData({
              type: overrides.type ?? "webauthn.create",
              challenge: overrides.challenge ?? options.challenge,
              origin: overrides.origin ?? origin,
            }),
          ),
          attestationObject: b64u(attestationObject),
          transports: ["internal"],
        },
      };
    },

    // `options` is the optionsJSON from POST /api/authenticate/options.
    authenticate(options, { origin, overrides = {} }) {
      const id = overrides.credentialId ?? options.allowCredentials?.[0]?.id ?? credentials.keys().next().value;
      const credential = credentials.get(id) ?? credentials.values().next().value;
      const flags = overrides.flags ?? (FLAG_UP | FLAG_UV | (backedUp ? FLAG_BE | FLAG_BS : FLAG_BE));
      const data = authData({
        rpID: overrides.rpID ?? options.rpId,
        flags,
        signCount: overrides.signCount ?? 0,
      });
      const clientDataJSON = clientData({
        type: overrides.type ?? "webauthn.get",
        challenge: overrides.challenge ?? options.challenge,
        origin: overrides.origin ?? origin,
      });
      const signer = createSign("sha256");
      signer.update(Buffer.concat([data, sha256(clientDataJSON)]));
      const signingKey = overrides.signWith ?? credential.privateKey;
      let signature = signer.sign(signingKey);
      if (overrides.corruptSignature) signature = Buffer.concat([signature.subarray(0, -1), Buffer.from([signature.at(-1) ^ 0xff])]);
      return {
        id,
        rawId: id,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          clientDataJSON: b64u(clientDataJSON),
          authenticatorData: b64u(data),
          signature: b64u(signature),
          userHandle: overrides.userHandle ?? credential.userHandle,
        },
      };
    },
  };
}

export { FLAG_BE, FLAG_BS, FLAG_AT, FLAG_UP, FLAG_UV };
