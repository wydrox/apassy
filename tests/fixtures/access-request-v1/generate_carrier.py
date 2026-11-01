"""Synthetic vectors only: stdlib framing/RFC8439 AEAD + OpenSSL ECDSA, not product crypto.
Run here with python3 generate_carrier.py. Existing independent card/answer bytes stay exact.
"""
import base64
import hashlib
import json
import pathlib
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).parent
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
frame = lambda b: struct.pack(">I", len(b)) + b
compact = lambda x: json.dumps(x, ensure_ascii=False, separators=(",", ":")).encode()


def block(key, counter, nonce):
    words = list(struct.unpack("<16I", b"expand 32-byte k" + key + struct.pack("<I", counter) + nonce))
    x = words.copy()
    def qr(a, b, c, d):
        for i, j, k, rotate in [(a,b,d,16),(c,d,b,12),(a,b,d,8),(c,d,b,7)]:
            x[i] = (x[i] + x[j]) & 0xffffffff
            x[k] ^= x[i]
            x[k] = ((x[k] << rotate) | (x[k] >> (32-rotate))) & 0xffffffff
    for _ in range(10):
        for ids in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                    (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:
            qr(*ids)
    return struct.pack("<16I", *[(a+b)&0xffffffff for a,b in zip(words,x)])


def seal(key, nonce, aad, plain):
    ciphertext = b"".join(bytes(a^b for a,b in zip(plain[i:i+64],block(key,i//64+1,nonce))) for i in range(0,len(plain),64))
    poly = block(key,0,nonce)[:32]
    r = int.from_bytes(poly[:16],"little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    pad = lambda b: b + b"\0"*((-len(b))%16)
    message = pad(aad)+pad(ciphertext)+struct.pack("<QQ",len(aad),len(ciphertext))
    accumulator = 0
    for i in range(0,len(message),16):
        accumulator = ((accumulator+int.from_bytes(message[i:i+16]+b"\1","little"))*r)%((1<<130)-5)
    tag = ((accumulator+int.from_bytes(poly[16:],"little"))% (1<<128)).to_bytes(16,"little")
    return ciphertext+tag


card = json.loads((ROOT/"card-body.json").read_bytes())
vectors = json.loads((ROOT/"vectors.json").read_bytes())
receipt = dict(vault_id=card["vault_id"],team_id=card["team_id"],qid=card["qid"],request_id=card["request_id"],asker=card["asker"]["device"],digest=vectors["card_digest"],outcome="allowed_once",answered_by="6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",device_name="Test iPhone",device_kind="iphone",kind="allow_once",at=1790000031,expires_at=card["expires_at"])
body = compact(receipt)
assert len(body)<=512
s = hashlib.sha256(b"apassy-access-request-settle-v1\0"+frame(body)).digest()
message = b"apassy-access-request-settle-sign-v1\0"+s
# Published synthetic SEC1 key used by the original questions contract, never a live key.
private = bytes.fromhex("bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b")
public = base64.urlsafe_b64decode(vectors["public_key"]+"==")
der = bytes.fromhex("30770201010420")+private+bytes.fromhex("a00a06082a8648ce3d030107a144034200")+public
with tempfile.TemporaryDirectory() as temporary:
    key = pathlib.Path(temporary)/"synthetic.der";key.write_bytes(der)
    signature = subprocess.run(["/usr/bin/openssl","dgst","-sha256","-sign",str(key),"-keyform","DER"],input=message,check=True,stdout=subprocess.PIPE).stdout
wrapper = dict(protocol="apassy-access-request",v=1,part="settle",body=b64(body),digest=s.hex(),signature=b64(signature))
(ROOT/"settle-body.json").write_bytes(body)
(ROOT/"settle.json").write_bytes(compact(wrapper))
key = bytes(range(32)); team=card["team_id"];qid=card["qid"];kid=card["key_id"]
outer = {}
for index,(name,parts,filename) in enumerate([
    ("card",["apassy-question-v1","card",team,qid,kid,"member",str(card["expires_at"])],"card.json"),
    ("deny",["apassy-question-v1","answer",team,qid,kid,"3"],"deny.json"),
    ("allow_once",["apassy-question-v1","answer",team,qid,kid,"3"],"allow_once.json"),
    ("settle",["apassy-question-v1","settle",team,qid,kid],"settle.json")]):
    aad = "\0".join(parts).encode();nonce=bytes(range(index*12,index*12+12))
    outer[name]=dict(key_id=kid,nonce=b64(nonce),ciphertext=b64(seal(key,nonce,aad,(ROOT/filename).read_bytes())),aad_hex=aad.hex())
(ROOT/"carrier.json").write_bytes(json.dumps(outer,indent=2).encode()+b"\n")
