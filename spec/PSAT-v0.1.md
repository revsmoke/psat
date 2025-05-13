# Pre‑Signed Action Token (PSAT)

## Mini Specification v0.1 (Draft)

> **Status:** Draft for community feedback.
> **Authors:** Bryan Rice & ChatGPT (OpenAI)
> **License:** Creative Commons CC‑BY‑4.0

---

### 1  Purpose

Provide a browser‑friendly, secret‑less authentication pattern—similar to AWS S3 pre‑signed URLs—for *any* REST/GraphQL endpoint. A **PSAT** is a short‑lived, signed capability that authorises exactly one HTTP action (or a tightly scoped series of actions) without exposing long‑term credentials to client‑side JavaScript or WASM.

### 2  Scope & Non‑Goals

| In‑Scope                                            | Out‑of‑Scope                                 |
| --------------------------------------------------- | -------------------------------------------- |
| Signing & verifying a capability URL or header      | User identity federation (OAuth, SAML, etc.) |
| Support for JSON/HTTP APIs (REST, GraphQL)          | gRPC & raw TCP protocols (future work)       |
| Reference Edge‑worker vending + provider middleware | Full quota & billing design                  |
| Body‑hash binding & replay protection               | Revocation lists for >10 min tokens          |

### 3  Terminology

| Term                | Meaning                                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------- |
| **Vending Service** | Your edge/backend that mints PSATs. Holds the real API key.                                  |
| **Provider**        | API server that validates PSATs. Can be your service *or* a 3rd‑party willing to adopt PSAT. |
| **Consumer**        | Browser or WASM client calling the Provider using a PSAT.                                    |
| **PSAT**            | Pre‑Signed Action Token. A compact, tamper‑evident string (JWT/Biscuit/etc.).                |

### 4  High‑Level Flow

1. **Consumer ➜ Vending Service** — requests a PSAT for *method + path + body*.
2. **Vending Service** — verifies user/session, signs the PSAT, returns it.
3. **Consumer ➜ Provider** — performs the HTTP call, attaching PSAT via query param or header.
4. **Provider** — verifies signature & claims, executes action, returns response.

```text
Browser ---[no secret]---> Provider  X   (rejected)
Browser ---[PSAT]-------> Provider  √
```

### 5  PSAT Token Structure

**Note on path normalization:** The `p` (path) claim must be canonicalised before signing and verification. This includes decoding percent-encoded sequences, removing trailing slashes, collapsing duplicate slashes, and excluding the query string (i.e., the `p` value should only represent the pathname component). This ensures consistent verification and prevents subtle mismatches between issuing and receiving systems.

**Encoding:** JWS compact serialization (JWT) using EdDSA (`Ed25519`). Alternative formats (Biscuit, Macaroon) MAY be adopted in future versions. **Encoding:** JWS compact serialization (JWT) using EdDSA (`Ed25519`). Alternative formats (Biscuit, Macaroon) MAY be adopted in future versions.

#### 5.1  Required Claims

| Claim  | Type                  | Example                                                                   | Description                                    |
| ------ | --------------------- | ------------------------------------------------------------------------- | ---------------------------------------------- |
| `iss`  | string                | `edge.example.com`                                                        | Vending Service identifier / key id mapping    |
| `aud`  | string                | `api.example.com`                                                         | Hostname expected to verify the token          |
| `exp`  | int (sec since epoch) | `1715616000`                                                              | Absolute expiry, SHOULD be ≤ 5 min after `iat` |
| `iat`  | int                   | *autofilled*                                                              | Issued‑at                                      |
| `sub`  | string                | `user‑123`                                                                | End‑user or session id for logging & quota     |
| `m`    | string                | `POST`                                                                    | HTTP method (UPPERCASE, RFC 9110)              |
| `p`    | string                | `/v1/chat/completions`                                                    | Normalised request path                        |
| `bsha` | string                | SHA‑256 hex of the request body (empty body ➜ hash of zero‑length string) |                                                |

#### 5.2  Optional Claims

| Claim         | Purpose                                                                                            |
| ------------- | -------------------------------------------------------------------------------------------------- |
| `quota` (obj) | `{tokens:1024}` — provider‑specific usage budget                                                   |
| `origin`      | Bind PSAT to browser origin (`https://app.example.com`)                                            |
| `xhdr`        | Array of extra header names included in hash (e.g. `['Content‑Type']`)                             |
| `jti`         | Optional JWT ID — unique token ID for optional revocation tracking in memory (short TTL deny-list) |
| Claim         | Purpose                                                                                            |
| -------       | ---------                                                                                          |
| `quota` (obj) | `{tokens:1024}` — provider‑specific usage budget                                                   |
| `origin`      | Bind PSAT to browser origin (`https://app.example.com`)                                            |
| `xhdr`        | Array of extra header names included in hash (e.g. `['Content‑Type']`)                             |

### 6  Passing the Token

* **Query parameter** : `?sig=<psat>`
* **HTTP header** : `X‑PSAT: <psat>`

Provider MUST accept one form and MAY accept both. Query form is cache‑friendly; header form hides token from logs.

### 7  Signing Algorithms

| `alg`               | Key size      | Notes                                                        |
| ------------------- | ------------- | ------------------------------------------------------------ |
| `EdDSA` (`Ed25519`) | 32 byte pk    | Fast, small, collision‑resistant. **RECOMMENDED**            |
| `HS256`             | shared secret | Simpler deploy but secret must be in both Vender & Provider. |
| `ES256`             | P‑256         | FIPS‑friendly alternative                                    |

Public keys SHOULD be distributed via JWKS (`/.well‑known/jwks.json`).

### 8  Verification Procedure (Provider)

```pseudo
claims = verify_signature(psat)
assert now < claims.exp
assert req.method == claims.m
assert req.path   == claims.p
assert sha256(req.body) == claims.bsha
if claims.origin: assert req.header(Origin) == claims.origin
apply_quota(claims.sub, claims.quota)
```

Verification SHOULD be constant‑time to avoid timing attacks.

### 9  Security Considerations

* **TTL** — 1‑5 min recommended. Shorter if PSAT is embedded in HTML.
* **Body Hash** — prevents replay with altered payloads.
* **CORS** — provider MAY allow `*` when PSAT present; risk shifts to leaked token TTL.
* **Revocation** — keep `exp` short; for longer ops use `kid` + OCSP‑style revocation.
* **Logging** — avoid logging full PSAT; log `iat`, `sub`, `p`, `m` instead.

### 10  Example End‑to‑End Flow

```bash
# 1. Browser asks for capability
POST https://edge.example.com/delegate \
     -d '{"m":"POST","p":"/v1/chat/completions","body":<hash>}'

# ➜ returns JSON { "sig": "eyJhbGciOiJFZERTQSJ9…" }

# 2. Browser calls provider directly
curl -X POST 'https://api.example.com/v1/chat/completions?sig=eyJhbGci…' \
     -H 'Content-Type: application/json' \
     -d '{"messages":[…]}'
```

### 11  Test Vector

JWT header:

```json
{"alg":"EdDSA","typ":"JWT"}
```

Payload:

```json
{
  "iss":"edge.example.com",
  "aud":"api.example.com",
  "sub":"user‑123",
  "iat":1715612400,
  "exp":1715612700,
  "m":"POST",
  "p":"/v1/echo",
  "bsha":"e3b0c44298fc1c149afbf4c8996fb924…"
}
```

Signature (hex): `8421…`  *(Ed25519 sign of header||"."||payload)*

### 12  Reference Implementations

* **Edge Vending Service (TypeScript, Cloudflare Workers)** — `./examples/worker‑vending.ts`
* **Node.js Provider Middleware** — Express `verifyPsat()` example under `./examples/express‑provider.ts`
* **Browser Helper** — `psatFetch(method, path, body)` returns `Response`

### 13  Future Work

* Streaming bodies (chunked‑hash or SigV4‑style continuation)
* WebSocket & HTTP/3 DATAGRAM binding
* First‑party provider adoption & formal IETF draft

---

### 14  Changelog

| Version    | Date       | Notes          |
| ---------- | ---------- | -------------- |
|  0.1 Draft | 2025‑05‑13 | Initial sketch |

---

*Feedback & PRs welcome!*

---

## Appendix A  Security Analysis & Hardening Guide

> **Goal** — help reviewers answer: “If a PSAT leaks, how bad is it and how quickly can I contain the blast radius?”

### A.1 Threat‑Model Summary

| Actor                                   | Capability                     | Desired Mitigation                                                        |
| --------------------------------------- | ------------------------------ | ------------------------------------------------------------------------- |
| **Network eavesdropper** (passive)      | Reads PSAT in transit          | TLS 1.2+ (HTTP over TLS); short `exp`                                     |
| **Network attacker** (active)           | Replays or alters request body | Body‑hash `bsha`; signature over method+path; DPoP‑binding (future)       |
| **Malicious site embedding IMG/IFRAME** | Hot‑links PSAT URL             | `origin` claim; CSP & CORS control                                        |
| **Browser extension / XSS**             | Reads PSAT from JS context     | Least‑privilege TTL; disallow `X-PSAT` exposure via CORS response headers |
| **Insider with backend access**         | Reads JWKS private key         | Standard key‑management (KMS/HSM); rotation policy                        |

### A.2 Token Leakage Blast Radius

1. \*\*Time window = \*\*\`\` — default spec recommends ≤ 300 s.
2. Bound to **single (method,path,body)** tuple: replay on any other payload → verification fails.
3. *Optional* `origin` binds token to browser origin, thwarting XSRF‑style theft.
4. *Optional* DPoP‑style public‑key binding (future v0.2) would restrict use to same JS runtime instance.

### A.3 Recommended Defaults (Provider‑side)

Implementations SHOULD assume a maximum allowable clock skew of ±60 seconds when verifying the `iat` and `exp` claims, to accommodate minor desynchronization between client and server clocks.

| Setting                       | Safe Default                                            |
| ----------------------------- | ------------------------------------------------------- |
| `exp` TTL                     | ≤ 5 min (120 s ideal for interactive UI)                |
| Clock skew tolerance          | ± 60 s                                                  |
| Accepted algorithms           | `EdDSA` or `ES256` only                                 |
| Maximum body size per PSAT    | Application‑specific; enforce in claims (`quota.bytes`) |
| Max concurrent PSAT per `sub` | e.g. 5 outstanding to limit token hoarding              |
| Setting                       | Safe Default                                            |
| ---------                     | --------------                                          |
| `exp` TTL                     | ≤ 5 min (120 s ideal for interactive UI)                |
| Clock skew tolerance          | ± 60 s                                                  |
| Accepted algorithms           | `EdDSA` or `ES256` only                                 |
| Maximum body size per PSAT    | Application‑specific; enforce in claims (`quota.bytes`) |
| Max concurrent PSAT per `sub` | e.g. 5 outstanding to limit token hoarding              |

### A.4 Key Management & Rotation

* **JWKS versioning** — publish new key under fresh `kid`; overlap old+new for <24 h. During this grace period, providers MUST accept both the old and new keys for verification to prevent downtime during rotation.
* **Edge vendor key** should live in HSM/KMS; CI deploys JWKS automatically.
* **Rotation cadence** — rotate signing keys every 90 days at minimum; shorter if dictated by organizational policy or external audits.
* **Revocation** — publish `denylist` of `(kid, jti)` if medium‑TTL tokens become necessary; spec leaves this optional.
* **JWKS versioning** — publish new key under fresh `kid`; overlap old+new for <24 h.
* **Edge vendor key** should live in HSM/KMS; CI deploys JWKS automatically.
* **Revocation** — publish `denylist` of `(kid, jti)` if medium‑TTL tokens become necessary; spec leaves this optional.

### A.5 Audit Logging Template

```jsonl
{"ts":"2025-05-13T16:02:11Z","sub":"user-123","p":"/v1/chat","bytes":1420,"ms":823,"status":200}
```

*Never log the full PSAT string.*
Log minimal identifying fields: `sub`, `iat`, `exp`, `m`, `p`, sizes, latency, result.

### A.6 Interaction with Browser Security Headers

| Header                                             | Benefit                                                      |
| -------------------------------------------------- | ------------------------------------------------------------ |
| `Content-Security-Policy: frame-ancestors 'none'`  | Stops PSAT URLs being embedded in iframes by attackers       |
| `Referrer-Policy: strict-origin-when-cross-origin` | Prevent accidental leakage of PSAT via `Referer`             |
| `Permissions-Policy: cross-origin-isolated=()`     | Prevent other origins from inspecting SharedArrayBuffer etc. |

### A.7 Future Work – Security Extensions

1. **HTTP Message Signatures** integration → no query/header token at all; signature over full request inside standard `Signature` header.
2. **DPoP** public‑key‑bound PSAT → prevents replay even within TTL.
3. Formal security proofs once spec stabilises (ProVerif / Tamarin).
4. IETF draft submission & cryptographic review.

---
