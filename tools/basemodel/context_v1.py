"""Isolated sdc-text-v1 serialization. No torch import, secrets, or network access."""
import copy
import hashlib
import json
import random
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACT = HERE / 'contracts/secret-decision-context-v1.json'
TOKENIZER_SHA256 = '6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30'
REVISION = '55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851'
VOCAB = [
 ('kind', ['api_key', 'login', 'database', 'ssh_key', 'custom']),
 ('provider', ['<listed>', 'other', 'none']),
 ('env', ['local', 'development', 'staging', 'production', 'unknown']),
 ('env_from', ['owner', 'signal', 'usage', 'default', 'legacy_unknown', 'none']),
 ('scope', ['read_only', 'read_write', 'admin', 'unknown']),
 ('scope_from', ['owner', 'signal', 'usage', 'default', 'legacy_unknown', 'none']),
 ('sensitive', ['yes', 'no', 'unknown']), ('project', ['match', 'other', 'undeclared']),
 ('hosts', ['none', 'known', 'unknown']), ('made_by_agent', ['yes', 'not_recorded']),
 ('agent_used', ['yes', 'not_recorded']),
 ('secret_changed', ['none', 'lt1d', 'lt7d', 'lt30d', 'unknown']),
 ('access_changed', ['none', 'lt1d', 'lt7d', 'lt30d', 'unknown']),
 ('owner_allowed', ['0', '1', '2-4', '5+', 'unknown']),
 ('owner_denied', ['0', '1', '2-4', '5+', 'unknown']),
 ('owner_denied_other', ['0', '1', '2-4', '5+', 'unknown']), ('conflict', ['yes', 'no'])]
ACTIONS = ['read', 'change', 'deploy', 'delete']


class Unsupported(ValueError):
    """Invalid/unavailable evidence; messages never include input values."""


class Refusal(ValueError):
    def __init__(self, code, bound=None, room=None):
        self.code, self.bound, self.room = code, bound, room
        super().__init__(code)


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode('ascii')


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load_contract(path=CONTRACT):
    raw = Path(path).read_bytes()
    c = json.loads(raw)
    if raw != canonical(c) or c['name'] != 'secret-decision-context-v1' or c['serializer'] != 'sdc-text-v1':
        raise Unsupported('contract identity/canonical encoding')
    if c['secret_facts'] != [[k, v] for k, v in VOCAB] or c['request_facts'] != [['action', ACTIONS], ['secrets', ['1', '2', '3']]]:
        raise Unsupported('contract vocabulary')
    if (c['base'] != {'repo': 'convaiinnovations/laya', 'revision': REVISION}
            or c['tokenizer']['sha256'] != TOKENIZER_SHA256
            or c['history'] != {'coverage': 'local_device', 'window_days': 30}
            or c['max_secrets'] != 3 or c['budget']['max_len'] != 512
            or c['budget']['agent_text_bound'] != 'ascii-1-nonascii-3x-utf8'
            or c['question'] != {'id': 'owner_accepts_use', 'type': 'noul', 'instructions': 'Would the owner allow this use of these credentials for the user request without being asked?'}):
        raise Unsupported('contract pins')
    providers = c['providers']
    if providers != sorted(set(providers)) or any(not re.fullmatch('[a-z0-9_-]+', p) or p == 'generic' for p in providers):
        raise Unsupported('provider vocabulary')
    for field in ('header_tokens', 'header_reserve_tokens'):
        n = c['budget'][field]
        if n is not None and (type(n) is not int or not 0 <= n <= 512):
            raise Unsupported('header budget')
    table = c['budget']['segment_tokens']
    if table is not None and (not isinstance(table, dict) or set(table) != set(all_segments(c)) or any(type(v) is not int or v < 0 for v in table.values())):
        raise Unsupported('segment table')
    return c


def contract_hash(c):
    return hashlib.sha256(canonical(c)).hexdigest()


def values(c, key, vocab):
    return c['providers'] + ['other', 'none'] if key == 'provider' else vocab


def validate_secret(secret, c):
    if not isinstance(secret, dict) or set(secret) != {k for k, _ in VOCAB}:
        raise Unsupported('secret schema')
    for k, vocab in VOCAB:
        if type(secret[k]) is not str or secret[k] not in values(c, k, vocab):
            raise Unsupported('unrecognized fact')


def state_text(request):
    # Input is already sanitized, just as on the Rust side. instruction is ignored.
    for k in ('user_request', 'command', 'purpose'):
        if type(request.get(k)) is not str:
            raise Unsupported('request schema')
    text = 'User request: "' + request['user_request'].strip() + '". Shell command: `' + request['command'] + '`.'
    if request['purpose'].strip():
        text += " Agent's stated purpose: " + request['purpose'].strip()
    return text


def segments(action, secrets, c):
    if action not in ACTIONS or type(action) is not str:
        raise Unsupported('action vocabulary')
    if not secrets:
        raise Refusal('NoSecrets')
    if len(secrets) > 3:
        raise Refusal('TooManySecrets')
    parts = [' Context:', ' action=' + action, ' secrets=' + str(len(secrets)),
             ' history=local_device', ' window=30d.']
    for i, secret in enumerate(secrets, 1):
        validate_secret(secret, c)
        parts.append(' secret_' + str(i) + ':')
        parts.extend(' ' + k + '=' + secret[k] + ('.' if k == 'conflict' else '') for k, _ in VOCAB)
    return parts


def all_segments(c):
    out = [' Context:', ' history=local_device', ' window=30d.']
    out += [' action=' + a for a in ACTIONS]
    out += [' secrets=' + str(n) for n in range(1, 4)]
    out += [' secret_' + str(n) + ':' for n in range(1, 4)]
    for k, v in VOCAB:
        out += [' ' + k + '=' + x + ('.' if k == 'conflict' else '') for x in values(c, k, v)]
    return sorted(set(out))


def agent_text_bound(text):
    return sum(1 if ord(ch) < 128 else 3 * len(ch.encode('utf-8')) for ch in text)


def serialize(request, action, secrets, c, enforce_budget=True):
    state = state_text(request)
    parts = segments(action, secrets, c)
    table = c['budget']['segment_tokens']
    cost = sum(table[s] for s in parts) if table is not None else len(''.join(parts).encode('ascii'))
    bound = agent_text_bound(state) + cost
    header = c['budget']['header_tokens']
    room = c['budget']['max_len'] - (c['budget']['header_reserve_tokens'] if header is None else header)
    if enforce_budget and bound > room:
        raise Refusal('OverBudget', bound, room)
    return state + ''.join(parts), bound


def blind(secrets, c):
    """Remove all information, including kind and conflict (vocab has no unknown)."""
    out = []
    for secret in secrets:
        validate_secret(secret, c)
        row = {}
        for k, v in VOCAB:
            row[k] = next((x for x in ('unknown', 'none', 'not_recorded', '0', 'undeclared', 'no') if x in v), v[0])
        out.append(row)
    return out


def tokenizer_tools(base, c):
    """Tokenizer/config only: never instantiates Agent or loads model weights."""
    from importlib.metadata import version
    if version('laya') != '0.3.20':
        raise Unsupported('Laya version')
    from transformers import AutoTokenizer
    from laya.agent import Agent
    from laya.common import build_sequence, serialize_state
    base = Path(base)
    if sha256(base / c['tokenizer']['path']) != c['tokenizer']['sha256']:
        raise Unsupported('tokenizer pin')
    tok = AutoTokenizer.from_pretrained(str(base / 'tokenizer'), local_files_only=True)
    cfg = json.loads((base / 'rl_agent_config.json').read_text())
    if cfg.get('max_len', 512) != 512:
        raise Unsupported('model context size')
    question = {k: v for k, v in c['question'].items() if k != 'id'}
    header, _ = build_sequence(tok, '', Agent._to_internal(question), 512,
                               cfg.get('head_max_len', 192), state_ids=[])
    return tok, len(header), serialize_state


def measure(base, c, fuzz=10000):
    tok, header, identity = tokenizer_tools(base, c)
    count = lambda s: len(tok(s, add_special_tokens=False)['input_ids'])
    proposed = copy.deepcopy(c)
    table = {s: count(s) for s in all_segments(c)}
    proposed['budget']['header_tokens'] = header
    proposed['budget']['segment_tokens'] = table
    if header > 512:
        raise Unsupported('question header exceeds context')
    rng = random.Random(571)
    alphabet = ['a', ' ', '  ', '\n', 'é', 'e\u0301', '\u0344', '\ufb03', '界', '🦦', '\t', '<mask>']
    for _ in range(fuzz):
        state = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(100)))
        if identity(state) != state or count(state) > agent_text_bound(state):
            raise Unsupported('state identity or Unicode bound violation')
        secrets = [{k: rng.choice(values(c, k, v)) for k, v in VOCAB} for _ in range(rng.randint(1, 3))]
        parts = segments(rng.choice(ACTIONS), secrets, c)
        if count(''.join(parts)) != sum(table[p] for p in parts):
            raise Unsupported('segment additivity violation')
        if count(state + ''.join(parts)) > agent_text_bound(state) + sum(table[p] for p in parts):
            raise Unsupported('full bound violation')
    return proposed, {'fuzz_cases': fuzz, 'header_tokens': header, 'tokenizer_sha256': TOKENIZER_SHA256,
                      'proposed_contract_sha256': contract_hash(proposed)}
