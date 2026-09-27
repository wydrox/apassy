# ADR 0011 — Placeholders and a proxy for each run

Date: 2026-09-27.
Status: ACCEPTED by the owner on 2026-09-27 ("Yes, start"). Stage 1 (the proxy, the placeholder mode, and the macOS network rule) is in the code. The later stages are below.

## Context

ADR 0006 puts the real value of a secret into the environment of one process. The owner approves the command text, not what the process does with the value. On 2026-09-27 the owner and the agent listed the ways out:

- Each child process inherits the environment. `npm test` runs package scripts that a dependency can change.
- A process of the same user can read the environment of a running process of another program (F11, ADR 0006). The agent runs as the same user. Measured again on 2026-09-27: `ps -E` shows a canary in the environment of a running `node` process. It does not show the environment of an Apple program such as `/bin/sleep`.
- A process can print, encode, save, or send the value. Output masking finds only the exact value.

The owner asked for a solution for macOS, Linux, and Windows, and compared it with Meta Muse. In Muse ([Meta, "How We Built Safety Into Muse"](https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse)) the agent code sees only a surrogate token. The proxy (Sentinel) checks each request and puts the real credential in at the network boundary. Meta controls the whole VM, so no program can go around Sentinel.

The owner proposed the Apassy form: Apassy runs the command through its own proxy. The proxy knows each placeholder of the run, so it does not need to look at other traffic, and no real value is in the process or its environment.

## Decision

### 1. Two modes for each variable

The owner selects the mode of each environment variable (schema version 11, column `env_binding.placeholder_hosts`):

| Mode | The process gets | The real value goes |
| --- | --- | --- |
| Real value (ADR 0006) | the value | anywhere that the process sends it |
| Placeholder | a placeholder | only into HTTPS requests to the hosts of the variable |

The hosts are `host` (port 443) or `host:port`, 1 to 16, lowercase. A host covers its subdomains. The app fills them from the known hosts of the provider of the item. A new variable starts in placeholder mode when those hosts are known. A change of the mode or the hosts needs the owner check (goal item A4), as each variable change does.

### 2. The placeholder

- It has the length of the value, so the proxy can swap it in both directions without a change of framing.
- It keeps a listed vendor prefix (for example `sk_live_`, `ghp_`, `sk-ant-`), because some tools read the prefix (the Stripe tools select live or test mode by it). An unlisted prefix is not kept, so the placeholder never repeats a random part of a value.
- The rest is random. It keeps the alphabet of the value (digits, hexadecimal, or letters and digits) and the places of `-`, `_`, `.`, and `=`.
- It needs at least 64 random bits. A shorter value (a short password) cannot use placeholder mode.
- Each run gets new placeholders. A placeholder is worth nothing after its run.

### 3. The proxy of a run

The broker starts one proxy for each run with a placeholder variable (`src/broker/proxy/`). It stops at the end of the run and closes each connection.

- It listens on `127.0.0.1` on a free port. It needs the password of the run (`Proxy-Authorization`).
- Each run has a new certificate authority: an ECDSA key in the memory of the broker, valid for one day, with name constraints for the hosts of the run. The process gets only its certificate, as a file.
- `CONNECT` to a host of a variable: the proxy ends the TLS connection with a certificate for the host, and opens its own TLS connection to the host. It checks that connection with the system trust store, as the connector does (ADR 0005), and it finishes the handshake before it sends a byte. It sends no value when the check fails.
- The real value goes only into an auth position:
  - the `Authorization` header: the whole value, `<scheme> <placeholder>`, or Basic with the placeholder as the user name or the password;
  - a known API key header (`X-Api-Key`, `Api-Key`, `Private-Token`, `X-Goog-Api-Key`, and others);
  - a known key parameter of the query (`key`, `api_key`, `access_token`, `token`, and others).
- The proxy stops a request with `403` and the header `X-Apassy-Proxy: refused` when:
  - a placeholder is in another header, in the path, or in another query parameter;
  - a placeholder is in the request body. The proxy stops before it sends the piece with the placeholder. A body would make the placeholder, or later the real value, data that the service stores or returns;
  - a placeholder goes to a host that its variable is not for;
  - the `Host` header does not match the `CONNECT` host, or the request asks for a protocol upgrade (WebSocket).
- In an answer, the proxy puts the placeholder back in place of each real value of the run, in the head and in the body. It removes `Accept-Encoding` from requests, so the answer is not compressed. A compressed answer is not checked, and the log says so. The answer flows as a stream (server-sent events): the proxy holds back only an end of a piece that can be the start of a real value.
- The proxy keeps the connection to the service between requests. When the service closed it in the meantime, a request without a body gets one more try on a new connection.
- Other hosts get a tunnel without a look inside (the default), or a refusal. Plain `http://` to a host of a variable is refused. Plain `http://` to another host is sent on without a change.
- The HTTP/1.1 parser is strict: a request with both `Content-Length` and `Transfer-Encoding`, a folded header, or a coding other than `chunked` is refused, so the proxy and the service cannot see different request borders. The proxy offers only HTTP/1.1 (ALPN).

### 4. How the process uses the proxy

The process gets these variables: `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` (upper and lower case) with the proxy address and password, an empty `NO_PROXY`, `NODE_USE_ENV_PROXY=1`, `NODE_EXTRA_CA_CERTS` (the run authority), and `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` (the system bundle and the run authority). A binding cannot use these names.

On macOS the process starts in a Seatbelt profile that denies each outgoing connection except the one to the proxy port: no other host, no other loopback port, no Unix socket. A program that ignores `HTTPS_PROXY` has no network. The profile has no other rule.

### 5. The log

The run answer has `placeholders` and `network.requests`: for each request the host, the method, the path without the query, the status, the outcome (`swapped`, `passed`, `tunneled`, `refused`, `failed`), the variables whose value went in, and a reason. The activity log gets one sentence with the counts. No entry has a value or a placeholder.

## Measured on 2026-09-27 (macOS, this computer)

| Program | Result |
| --- | --- |
| curl 8 (system) | uses the proxy and the trust file; works |
| Python 3.12 with OpenSSL 3 (Homebrew), `urllib` | works |
| Node 22.23, `fetch` and `https` | uses the proxy only with `NODE_USE_ENV_PROXY=1` (set by Apassy); works |
| Apple Python 3.9 (LibreSSL 2.8.3, `/usr/bin/python3`) | ignores `SSL_CERT_FILE`; the TLS check fails, and no request reaches the service (fails closed) |
| A Go program (`net/http`, as in `gh`) | uses the proxy; the TLS check fails with "certificate signed by unknown authority", because Go on macOS and Windows reads only the system trust store; no request reaches the service, and the log names the reason (fails closed). For `localhost` Go does not use a proxy, and the macOS rule stops the direct connection |
| `vercel` 54.21.1 | without `NODE_USE_ENV_PROXY` it ignores the proxy; with it, only its telemetry went through the proxy |
| A direct connection in the Seatbelt profile (curl `--noproxy '*'`, a Python socket) | refused: `Operation not permitted` |

Tests: `tests/run_proxy.rs` (curl, Python, Node, answers with a real value, refusals, tunnels, the password, the macOS rule, a client that fails closed) and `a_placeholder_variable_gets_a_placeholder_and_the_run_proxy` in `tests/agent_run.rs`.

## What this mode does not protect

- A program that does not use the proxy or does not trust the run authority fails. It does not leak: it has only placeholders. For such programs (Go on macOS, Apple Python 3.9, Java, programs that pin certificates) the owner selects the real value.
- A same-user process can read the environment of the run (F11): the proxy address, the password, and the placeholders. While the run lasts, it can send requests through the proxy. It gets only what the swap rules allow, each request is in the log, and it never gets the value.
- A request signed with the secret (AWS SigV4), a protocol other than HTTP (databases), HTTP/2 only (gRPC), and a value that the program uses itself (a JWT signing secret, a webhook secret) need the real value.
- A transfer of a secret to another service (`vercel env add`) sends the value in a body, so the proxy refuses it. Stage 3 adds named actions for this.
- In the default tunnel mode, the process can send other data (for example files) to other hosts. The log names each host. On Linux there is no network rule yet, and the codebase does not build for Windows.
- The broker process holds the values during the run.

## Next stages

1. Done: the proxy, the placeholder mode, the macOS network rule, the app setting, and the log.
2. Linux: a network namespace (bubblewrap or `unshare`) with a relay to the proxy, so a program has no other route.
3. Named actions for transfers: the proxy puts the value into the body of one request that the owner approved ("Stripe key to api.vercel.com"), or Apassy calls the API itself. `gh secret set` encrypts the value before it sends it, so it needs the action.
4. Go on macOS and Windows: an optional install of a name-constrained Apassy authority in the user trust store, or a base URL on loopback for tools that have one (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`).
5. HTTP/2 and WebSocket in the proxy.
6. Hardening of the broker process on each system: the hardened runtime on macOS, `PR_SET_DUMPABLE=0` on Linux, a service account on Windows.
7. Cloud: the same design with the proxy on another computer, so the computer of the agent holds only placeholders.

## Dependencies

`rcgen 0.14.10` (features `crypto`, `pem`, `ring`) and `time 0.3.47` join the `vault` feature. They add `rcgen`, `pem`, `base64 0.23`, `yasna`, `time`, `time-core`, `deranged`, `num-conv`, and `powerfmt`. There is no async runtime. The TLS stays `rustls` with `ring` (ADR 0005). ADR 0001 forbids a custom cipher or TLS implementation; the proxy has none. Its HTTP/1.1 parser is new code.

## Relation to other records

- ADR 0006 stays valid. Its mode is now "real value", and it stays the default for a variable without known hosts.
- ADR 0005 stays valid. The proxy uses the same verifier for the services.
- The limit F11 (ADR 0010) stays for the real value mode. In placeholder mode it gives only placeholders.
