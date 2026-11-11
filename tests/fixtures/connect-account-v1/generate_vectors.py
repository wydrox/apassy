"""Makes tests/fixtures/connect-account-v1/vectors.json (docs/contracts/connect-account-v1.md
section 15). Synthetic keys only.

Run from the repository root with OpenSSL 3 on PATH (or OPENSSL=/path/to/openssl):

    python3 -I tests/fixtures/connect-account-v1/generate_vectors.py

ECDSA signatures are randomized: a new run gives other signatures that still verify.
The Ed25519 signatures (the entitlement tokens and the recovery signature) are
deterministic. The recovery code is the seed of an Ed25519 key:
SHA-256("apassy-connect recovery key v1" 0x00 <16 bytes>). The word list is
read from docs/contracts/relay-sync-v1.md section 16.
"""

import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = ROOT / "tests/fixtures/connect-account-v1/vectors.json"
OPENSSL = os.environ.get("OPENSSL", "openssl")

ORIGIN = "https://connect.example.test"
BRAIN_ORIGIN = "https://brain.example.test"
ACCOUNT = "acc_k7m2q4x3ca"
# Device A: the device key of the relay-sync-v1 vectors (section 15).
PRIV_A = "4f2d9c6e1b3a7d8f0c5e2a9b7f4d1c3e6a8b0d2f4c6e8a1b3d5f7a9c0e2b4d6f"
# Device B: another synthetic scalar.
PRIV_B = "1c9a5e3f7b2d4a6c8e0f1a3b5c7d9e2f4a6b8c0d1e3f5a7b9c2d4e6f8a1b3c5d"
NONCE = bytes(range(32))
# The secret part of the link code; the code ends with the fingerprint of the keys.
LINK_CODE = "apassy_alk_" + ACCOUNT + "_" + "cd" * 32
RECOVERY = bytes(range(16, 32))
# The recovery code that a recovery puts in the place of RECOVERY.
NEW_RECOVERY = bytes(range(64, 80))
ED_SEED = bytes(range(32, 64))
KID = "ek_test_1"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def join(*parts) -> bytes:
    out = b""
    for i, part in enumerate(parts):
        if i:
            out += b"\0"
        out += part if isinstance(part, bytes) else part.encode()
    return out


def words():
    text = (ROOT / "docs/contracts/relay-sync-v1.md").read_text()
    block = text.split("## 16. The word list", 1)[1].split("```", 2)[1]
    found = block.split()
    assert len(found) == 256 and len(set(found)) == 256
    return found


def openssl(*args, data=None):
    return subprocess.run(
        [OPENSSL, *args], input=data, check=True, capture_output=True
    ).stdout


def ec_key(priv_hex: str, tmp: pathlib.Path, name: str):
    # ECPrivateKey (RFC 5915) without the public key; OpenSSL derives the point.
    der = (
        bytes.fromhex("30310201010420")
        + bytes.fromhex(priv_hex)
        + bytes.fromhex("a00a06082a8648ce3d030107")
    )
    path = tmp / f"{name}.der"
    path.write_bytes(der)
    pem = tmp / f"{name}.pem"
    openssl("ec", "-inform", "DER", "-in", str(path), "-out", str(pem))
    spki = openssl("ec", "-in", str(pem), "-pubout", "-outform", "DER")
    point = spki[-65:]
    assert point[0] == 4
    return pem, point


def ecdsa(pem: pathlib.Path, message: bytes, point: bytes, tmp: pathlib.Path) -> bytes:
    msg = tmp / "msg.bin"
    msg.write_bytes(message)
    sig = openssl("dgst", "-sha256", "-sign", str(pem), str(msg))
    pub = tmp / "pub.pem"
    pub.write_bytes(openssl("ec", "-in", str(pem), "-pubout"))
    sig_path = tmp / "sig.der"
    sig_path.write_bytes(sig)
    openssl("dgst", "-sha256", "-verify", str(pub), "-signature", str(sig_path), str(msg))
    return sig


def ed25519(seed: bytes, message: bytes, tmp: pathlib.Path):
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    path = tmp / "ed.der"
    path.write_bytes(der)
    pem = tmp / "ed.pem"
    openssl("pkey", "-inform", "DER", "-in", str(path), "-out", str(pem))
    public = openssl("pkey", "-in", str(pem), "-pubout", "-outform", "DER")[-32:]
    msg = tmp / "ed-msg.bin"
    msg.write_bytes(message)
    sig = openssl("pkeyutl", "-sign", "-inkey", str(pem), "-rawin", "-in", str(msg))
    assert len(sig) == 64
    return public, sig


def token(claims: dict, tmp: pathlib.Path):
    payload = b64u(json.dumps(claims, separators=(",", ":")).encode())
    public, sig = ed25519(ED_SEED, join("apassy-connect entitlement v1", payload), tmp)
    return public, payload, b64u(sig), payload + "." + b64u(sig)


def message(name, tag, signer, data, pem, point, tmp):
    return {
        "name": name,
        "tag": tag,
        "signer": signer,
        "message_b64u": b64u(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "signature_b64u": b64u(ecdsa(pem, data, point, tmp)),
    }


def recovery_key(code: bytes, tmp: pathlib.Path):
    """The Ed25519 key of a recovery code: its public key and its seed."""
    seed = hashlib.sha256(join("apassy-connect recovery key v1", code)).digest()
    public, _ = ed25519(seed, b"probe", tmp)
    return seed, public


def main():
    wl = words()
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = pathlib.Path(tmp_name)
        pem_a, pub_a = ec_key(PRIV_A, tmp, "a")
        pem_b, pub_b = ec_key(PRIV_B, tmp, "b")
        a64, b64 = b64u(pub_a), b64u(pub_b)
        nonce = b64u(NONCE)

        # The link code of device A (the account root, which also confirms).
        fingerprint = hashlib.sha256(join("apassy-connect link-keys v1", pub_a, pub_a)).digest()[:16].hex()
        link_code = LINK_CODE + "_" + fingerprint
        assert len(link_code) == 123
        link_hash = b64u(hashlib.sha256(join("apassy-connect link v1", link_code)).digest())
        safety = hashlib.sha256(
            join("apassy-connect safety v1", ACCOUNT, link_code, pub_a, pub_b)
        ).digest()

        seed, rec_public = recovery_key(RECOVERY, tmp)
        new_seed, new_public = recovery_key(NEW_RECOVERY, tmp)
        rec64, new64 = b64u(rec_public), b64u(new_public)

        create = join("apassy-connect account v1", ORIGIN, a64, rec64)
        sign_in = join("apassy-connect sign-in v1", ORIGIN, ACCOUNT, a64, nonce)
        join_msg = join("apassy-connect join v1", ORIGIN, ACCOUNT, link_hash, b64)
        cancel = join("apassy-connect join-cancel v1", ORIGIN, ACCOUNT, link_hash, b64)
        # The signed device list: A is the root (version 1), A adds B (2), A removes B (3).
        root = join("apassy-connect device-list v1", ORIGIN, ACCOUNT, "1", "-", "root", a64, "-", a64)
        root_hash = b64u(hashlib.sha256(root).digest())
        add = join("apassy-connect device-list v1", ORIGIN, ACCOUNT, "2", root_hash, "add", b64, link_hash, a64)
        add_hash = b64u(hashlib.sha256(add).digest())
        remove = join("apassy-connect device-list v1", ORIGIN, ACCOUNT, "3", add_hash, "remove", b64, "-", a64)
        remove_hash = b64u(hashlib.sha256(remove).digest())
        recover = join("apassy-connect recover v1", ORIGIN, ACCOUNT, b64, new64)
        brain = join("apassy-bouncer sign-in v1", BRAIN_ORIGIN, ACCOUNT, a64, nonce)
        _, recover_signature = ed25519(seed, recover, tmp)

        messages = [
            message("account", "apassy-connect account v1", "device_a", create, pem_a, pub_a, tmp),
            message("sign_in", "apassy-connect sign-in v1", "device_a", sign_in, pem_a, pub_a, tmp),
            message("join", "apassy-connect join v1", "device_b", join_msg, pem_b, pub_b, tmp),
            message("join_cancel", "apassy-connect join-cancel v1", "device_b", cancel, pem_b, pub_b, tmp),
            message("device_list_add", "apassy-connect device-list v1", "device_a", add, pem_a, pub_a, tmp),
            message("device_list_remove", "apassy-connect device-list v1", "device_a", remove, pem_a, pub_a, tmp),
            message("recover", "apassy-connect recover v1", "device_b", recover, pem_b, pub_b, tmp),
            message("brain_sign_in", "apassy-bouncer sign-in v1", "device_a", brain, pem_a, pub_a, tmp),
        ]
        add_signature = next(m for m in messages if m["name"] == "device_list_add")["signature_b64u"]
        remove_signature = next(m for m in messages if m["name"] == "device_list_remove")["signature_b64u"]

        personal = {
            "v": 1,
            "kid": KID,
            "acc": ACCOUNT,
            "plan": "personal",
            "group": None,
            "feats": ["brain", "sync", "tunnel"],
            "iat": 1790000000,
            "exp": 1790086400,
        }
        family = dict(personal, acc="acc_m3n5p7q2rb", plan="family", group="grp_f4m6n2p7qa")
        ed_public, p_payload, p_sig, p_token = token(personal, tmp)
        _, f_payload, f_sig, f_token = token(family, tmp)

        vectors = {
            "origin": ORIGIN,
            "brain_origin": BRAIN_ORIGIN,
            "account_id": ACCOUNT,
            "device_a": {
                "device_id": "dev_m2k7q3x4ab",
                "private_hex": PRIV_A,
                "public_hex": pub_a.hex(),
                "public_b64u": a64,
                "public_key_sha256": hashlib.sha256(pub_a).hexdigest(),
            },
            "device_b": {
                "device_id": "dev_p4n6r2t7bc",
                "private_hex": PRIV_B,
                "public_hex": pub_b.hex(),
                "public_b64u": b64,
                "public_key_sha256": hashlib.sha256(pub_b).hexdigest(),
            },
            "nonce_b64u": nonce,
            "messages": messages,
            "link": {
                "code": link_code,
                "link_hash": link_hash,
                "root": "device_a",
                "confirmer": "device_a",
                "fingerprint": fingerprint,
            },
            "device_list": {
                "root_message_b64u": b64u(root),
                "entries": [
                    {"version": 1, "op": "root", "key": a64, "link_hash": None, "by": a64, "signature": None},
                    {"version": 2, "op": "add", "key": b64, "link_hash": link_hash, "by": a64, "signature": add_signature},
                    {"version": 3, "op": "remove", "key": b64, "link_hash": None, "by": a64, "signature": remove_signature},
                ],
                "hashes": [root_hash, add_hash, remove_hash],
                "live_at": {"1": ["device_a"], "2": ["device_a", "device_b"], "3": ["device_a"]},
            },
            "safety": {
                "sha256": safety.hex(),
                "words": " ".join(wl[b] for b in safety[:6]),
            },
            "recovery": {
                "bytes_hex": RECOVERY.hex(),
                "code": "apassy_rec_" + RECOVERY.hex(),
                "words": " ".join(wl[b] for b in RECOVERY),
                "seed_hex": seed.hex(),
                "public_b64u": rec64,
                "recover_signature_b64u": b64u(recover_signature),
            },
            "new_recovery": {
                "bytes_hex": NEW_RECOVERY.hex(),
                "seed_hex": new_seed.hex(),
                "public_b64u": new64,
            },
            "entitlement": {
                "kid": KID,
                "seed_hex": ED_SEED.hex(),
                "public_b64u": b64u(ed_public),
                "tokens": [
                    {
                        "name": "personal",
                        "claims": personal,
                        "payload_b64u": p_payload,
                        "signature_b64u": p_sig,
                        "token": p_token,
                    },
                    {
                        "name": "family_member",
                        "claims": family,
                        "payload_b64u": f_payload,
                        "signature_b64u": f_sig,
                        "token": f_token,
                    },
                ],
            },
        }
    OUT.write_text(json.dumps(vectors, indent=2) + "\n")


if __name__ == "__main__":
    main()
