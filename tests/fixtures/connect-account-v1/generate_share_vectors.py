"""Makes tests/fixtures/connect-account-v1/share-vectors.json (docs/contracts/connect-account-v1.md
sections 15 and 16): the byte layouts of a vault shared between two accounts. Synthetic keys only.

Run from the repository root with OpenSSL 3 on PATH (or OPENSSL=/path/to/openssl):

    python3 -I tests/fixtures/connect-account-v1/generate_share_vectors.py

Account A (`acc_k7m2q4x3ca`, root device A) shares the store `t_7k2m5q4x3c` with account X
(`acc_m3n5p7q2rb`, root device B, the family member of vectors.json):

- A's list: the root (version 1), `peer X <root B>` (2), `store <store>` (3, no account, no root),
  `share X <store>` (4), each signed by A.
- X's list: the root (1), `peer A <root A>` (2), `join A <store>` (3) naming in its root field the list
  hash of A's `share` (version 4), each signed by B.
- A's share code with the share fingerprint of A's root and device A, its link hash, B's signed
  `apassy-connect peer-join v1` answer, and the six share words.

ECDSA signatures are randomized: a new run gives other signatures that still verify. The keys and
the word list are those of generate_vectors.py.
"""

import hashlib
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import generate_vectors as base  # noqa: E402

OUT = base.ROOT / "tests/fixtures/connect-account-v1/share-vectors.json"
STORE = "t_7k2m5q4x3c"
ACCOUNT_A = base.ACCOUNT
ACCOUNT_X = base.MEMBER_ACCOUNT
# The secret part of the share code; the code ends with the share fingerprint.
SHARE_CODE = "apassy_shr_" + ACCOUNT_A + "_" + "ef" * 32


def h(data: bytes) -> str:
    return base.b64u(hashlib.sha256(data).digest())


def share_list(account, version, previous, op, peer, root, team, by):
    return base.join(
        "apassy-connect share-list v1",
        base.ORIGIN,
        account,
        str(version),
        previous,
        op,
        peer,
        root or "-",
        team or "-",
        by,
    )


def main():
    wl = base.words()
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = pathlib.Path(tmp_name)
        pem_a, pub_a = base.ec_key(base.PRIV_A, tmp, "a")
        pem_b, pub_b = base.ec_key(base.PRIV_B, tmp, "b")
        a64, b64 = base.b64u(pub_a), base.b64u(pub_b)

        def sign(pem, point, data):
            return base.b64u(base.ecdsa(pem, data, point, tmp))

        # A's list.
        a_root = base.join("apassy-connect device-list v1", base.ORIGIN, ACCOUNT_A, "1", "-", "root", a64, "-", base.NAME_A, a64)
        a_peer = share_list(ACCOUNT_A, 2, h(a_root), "peer", ACCOUNT_X, b64, None, a64)
        a_store = share_list(ACCOUNT_A, 3, h(a_peer), "store", "-", None, STORE, a64)
        a_share = share_list(ACCOUNT_A, 4, h(a_store), "share", ACCOUNT_X, None, STORE, a64)
        # X's list.
        x_root = base.join("apassy-connect device-list v1", base.ORIGIN, ACCOUNT_X, "1", "-", "root", b64, "-", base.NAME_B, b64)
        x_peer = share_list(ACCOUNT_X, 2, h(x_root), "peer", ACCOUNT_A, a64, None, b64)
        x_join = share_list(ACCOUNT_X, 3, h(x_peer), "join", ACCOUNT_A, h(a_share), STORE, b64)

        fingerprint = hashlib.sha256(base.join("apassy-connect share-keys v1", pub_a, pub_a)).digest()[:16].hex()
        code = SHARE_CODE + "_" + fingerprint
        assert len(code) == 123
        link_hash = h(base.join("apassy-connect share-link v1", code))
        peer_join = base.join("apassy-connect peer-join v1", base.ORIGIN, ACCOUNT_A, link_hash, ACCOUNT_X, b64, b64)
        safety = hashlib.sha256(
            base.join("apassy-connect share-safety v1", code, ACCOUNT_A, pub_a, pub_a, ACCOUNT_X, pub_b, pub_b)
        ).digest()

        messages = [
            base.message("share_list_peer", "apassy-connect share-list v1", "device_a", a_peer, pem_a, pub_a, tmp),
            base.message("share_list_store", "apassy-connect share-list v1", "device_a", a_store, pem_a, pub_a, tmp),
            base.message("share_list_share", "apassy-connect share-list v1", "device_a", a_share, pem_a, pub_a, tmp),
            base.message("share_list_member_peer", "apassy-connect share-list v1", "device_b", x_peer, pem_b, pub_b, tmp),
            base.message("share_list_join", "apassy-connect share-list v1", "device_b", x_join, pem_b, pub_b, tmp),
            base.message("peer_join", "apassy-connect peer-join v1", "device_b", peer_join, pem_b, pub_b, tmp),
        ]
        by_name = {m["name"]: m["signature_b64u"] for m in messages}

        def device_entry(version, key, name, signature):
            return {"version": version, "op": "root", "key": key, "link_hash": None, "name": name,
                    "by": key, "signature": signature}

        def share_entry(version, op, by, signature, peer, root=None, team=None):
            entry = {"version": version, "op": op, "key": None, "link_hash": None, "name": None,
                     "by": by, "signature": signature, "account_id": peer}
            if root is not None:
                entry["root"] = root
            if team is not None:
                entry["team_id"] = team
            return entry

        vectors = {
            "origin": base.ORIGIN,
            "account_a": ACCOUNT_A,
            "account_x": ACCOUNT_X,
            "store": STORE,
            "device_a": {"private_hex": base.PRIV_A, "public_hex": pub_a.hex(), "public_b64u": a64},
            "device_b": {"private_hex": base.PRIV_B, "public_hex": pub_b.hex(), "public_b64u": b64},
            "code": {"code": code, "fingerprint": fingerprint, "link_hash": link_hash,
                     "root": "device_a", "inviter": "device_a"},
            "words": {"sha256": safety.hex(), "words": " ".join(wl[b] for b in safety[:6]),
                      "joiner_root": "device_b", "joiner": "device_b"},
            "messages": messages,
            "lists": {
                "a": {
                    "entries": [
                        device_entry(1, a64, base.NAME_A, sign(pem_a, pub_a, a_root)),
                        share_entry(2, "peer", a64, by_name["share_list_peer"], ACCOUNT_X, root=b64),
                        share_entry(3, "store", a64, by_name["share_list_store"], None, team=STORE),
                        share_entry(4, "share", a64, by_name["share_list_share"], ACCOUNT_X, team=STORE),
                    ],
                    "hashes": [h(a_root), h(a_peer), h(a_store), h(a_share)],
                },
                "x": {
                    "entries": [
                        device_entry(1, b64, base.NAME_B, sign(pem_b, pub_b, x_root)),
                        share_entry(2, "peer", b64, by_name["share_list_member_peer"], ACCOUNT_A, root=a64),
                        share_entry(3, "join", b64, by_name["share_list_join"], ACCOUNT_A, root=h(a_share), team=STORE),
                    ],
                    "hashes": [h(x_root), h(x_peer), h(x_join)],
                },
            },
        }
    OUT.write_text(json.dumps(vectors, indent=2) + "\n")


if __name__ == "__main__":
    main()
