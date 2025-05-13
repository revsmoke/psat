# Pre-Signed Action Tokens (PSAT)  

* *Secret-less API capabilities for browser-first apps*

[![CI](https://github.com/your-handle/psat/actions/workflows/ci.yml/badge.svg)](./.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Spec Status](https://img.shields.io/badge/spec-v0.1%20draft-yellow)](spec/PSAT-v0.1.md)

> **TL;DR** – PSATs are short-lived, signed URLs (or headers) that authorise **one
> specific API call**—method, path, body, quota—without shipping long-term
> secrets to the browser or WASM client.  
> Think *“S3 pre-signed URL, but for any REST/GraphQL endpoint.”*

---

## ✨ Why PSAT?

| Pain today | How PSAT helps |
|------------|----------------|
| API keys or bearer tokens **exposed in client JS** | JS only receives a 1–5 minute, single-use capability token |
| CORS & custom domains | Provider can safely allow `*` when PSAT is present |
| Proxies add latency, file-upload headaches | Browser talks **directly** to the provider—no extra hop |
| Secret rotation is scary | Rotate signing keys behind the vending edge; clients unaffected |

---

## 🏗 How it Works (bird’s-eye)

1. **Browser** wants to make a `POST /v1/chat` request.

2. **Browser** sends a request to the **Vending Service** (e.g., Edge Worker or Lambda).

3. **Vending Service**:
   * Validates the user/session.
   * Signs a PSAT (JWT) for the specific API call.

4. **Browser** receives the PSAT and makes the API call:
   * `POST /v1/chat?sig=PSAT` → **Provider API**

**Flow Diagram:**

```text

+---------+       ① wants to do "POST /v1/chat"
| Browser |-----------------------------------+
+---------+                                    |
                                              \|/
                                     +------------------+
                                     |  Your Auth Edge  |  (holds real API key)
                                     +------------------+
                                      ② verifies user session
                                      ③ creates signed-action token
                                              \|/
+---------+   ④ fetch signed URL with body --->+------------------+
| Browser |----------------------------------->|   Provider API   |
+---------+          (no secret keys)          +------------------+

```

*Details live in **[spec/PSAT-v0.1.md](spec/PSAT-v0.1.md)**.*

---

## 🚀 Quick Start (dev sandbox)

```bash
git clone https://github.com/your-handle/psat.git
cd psat

# 1. Install dev tools & run tests
npm ci && npm test

# 2. Serve example browser page (uses a local Worker)
npm run dev   # starts Miniflare + HTTPS tunnel

# 3. In a new shell: call the provider with curl
curl -X POST 'https://localhost:8787/v1/echo' \
     -H 'Content-Type: application/json' \
     -d '{"msg":"hello"}'
```

### Under the hood

 1. Edge Worker (examples/edge-vending-worker.ts) checks your cookie/session,
generates a PSAT for POST /v1/echo, and responds with {"sig":"`jwt`"}.
 2. Browser helper (examples/browser-helper.js) appends the token to the real
provider URL and performs the fetch.
 3. Provider verifier (examples/express-provider.ts) validates the signature
& claims before echoing the payload.

⸻

### 🔐 Security in One Slide

* 1–5 minute TTL (exp)
* Method, path and SHA-256(body) locked in claims
* Optional origin ties token to a specific web origin
* Ed25519 signatures; public keys served via JWKS
* Full analysis in Appendix A of the spec

⸻

### Examples

Below are minimal, self-contained example files that compile under current Node 18 +/Deno/Cloudflare Workers stacks and demonstrate the PSAT flow end-to-end.

Naming / layout assumes

```text
src/examples/
├─ edge-vending-worker.ts   # Cloudflare Worker (token mint)
├─ express-provider.ts      # Node/Express API that verifies PSAT
└─ browser-helper.js        # Tiny fetch wrapper for the browser
```

---

#### edge-vending-worker.ts

```js
/**
 * Cloudflare Worker — PSAT “vending” service
 *
 * POST /delegate        ➜ { sig: "<PSAT JWT>" }
 * GET  /jwks.json       ➜ JWKS with the public Ed25519 key
 *
 * Environment variables:
 *   PRIVATE_KEY_PEM  Ed25519 PKCS8 PEM (one-line or multi-line)
 *   KEY_ID           Stable kid shown in JWKS  (e.g. "psat-1")
 *   AUDIENCE         Provider origin, e.g. "api.example.com"
 */

import { SignJWT, exportJWK, importPKCS8 } from 'jose'

export default {
  async fetch (req: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(req.url)

    /* ───────── JWKS endpoint ───────── */
    if (pathname === '/jwks.json') {
      const jwk = await getPublicJwk(env)
      return json({ keys: [jwk] }, 24 * 3600)       // cache 1 day
    }

    /* ───────── Capability mint ───────── */
    if (pathname === '/delegate' && req.method === 'POST') {
      const { m, p, bodySha, quota } = await req.json()

      // Basic validation
      if (!m || !p || !bodySha) {
        return json({ error: 'm, p, bodySha required' }, 400)
      }

      const iat = Math.floor(Date.now() / 1000)
      const exp = iat + 120            // 2-min TTL

      const payload: Record<string, unknown> = {
        sub: 'anon',                   // replace with your session id
        iat, exp, m, p,
        bsha: bodySha,
        ...(quota && { quota })
      }

      const priv = await importPrivateKey(env)
      const sig = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'EdDSA', kid: env.KEY_ID })
        .setIssuer('edge.psat') // iss
        .setAudience(env.AUDIENCE) // aud
        .sign(priv)

      return json({ sig })
    }

    /* ---------- fallback ---------- */
    return new Response('Not found', { status: 404 })
  }
}

/*──────────────── helpers ───────────────*/
interface Env {
  PRIVATE_KEY_PEM: string
  KEY_ID: string
  AUDIENCE: string
}

async function importPrivateKey (env: Env) {
  return importPKCS8(env.PRIVATE_KEY_PEM, 'EdDSA')
}

let cachedJwk: any
async function getPublicJwk (env: Env) {
  if (cachedJwk) return cachedJwk
  const priv = await importPrivateKey(env)
  const jwk = await exportJWK(priv)
  jwk.use = 'sig'
  jwk.alg = 'EdDSA'
  jwk.kid = env.KEY_ID
  cachedJwk = jwk
  return jwk
}

function json (data: unknown, maxAge = 0) {
  return new Response(JSON.stringify(data), {
    headers: {
      'content-type': 'application/json',
      ...(maxAge && { 'cache-control': `public, max-age=${maxAge}` })
    }
  })
}
```

Deploy with wrangler deploy (Cloudflare) or equivalent edge runtime.

#### express-provider.ts

```js
/**
 * Simple Express provider that verifies PSAT and echoes the body.
 * Endpoints:
 *   POST /v1/echo?sig=<psat>
 *
 * Env:
 *   JWKS_URL   — full URL to vending worker's /jwks.json
 *   AUDIENCE   — same audience string used in PSAT ('api.example.com')
 */

import express, { Request, Response, NextFunction } from 'express'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import crypto from 'crypto'

const { JWKS_URL, AUDIENCE = 'api.example.com' } = process.env
if (!JWKS_URL) throw new Error('JWKS_URL must be set')

/* Build a JWKS fetcher that auto-caches keys */
const JWKS = createRemoteJWKSet(new URL(JWKS_URL))

const app = express()
app.use(express.json({ limit: '2mb' }))

/* PSAT verification middleware */
async function verifyPsat (req: Request, res: Response, next: NextFunction) {
  try {
    const psat = req.query.sig as string ?? req.get('x-psat')
    if (!psat) throw new Error('Missing PSAT')

    /* Verify signature & audience/expiry */
    const { payload } = await jwtVerify(
      psat,
      JWKS,
      { audience: AUDIENCE, issuer: 'edge.psat' }
    )

    /* Method + path check */
    if (payload.m !== req.method) throw new Error('Method mismatch')
    if (payload.p !== req.path)   throw new Error('Path mismatch')

    /* Body hash check */
    const raw = JSON.stringify(req.body ?? {})
    const bsha = sha256Hex(raw)
    if (payload.bsha !== bsha) throw new Error('Body hash mismatch')

    /* Quota demo (tokens) */
    // TODO: implement real quota if payload.quota

    (req as any).psat = payload   // propagate if needed
    next()
  } catch (e) {
    res.status(401).json({ error: (e as any).message })
  }
}

/* Demo endpoint */
app.post('/v1/echo', verifyPsat, (req, res) => {
  res.json({ ok: true, echoed: req.body })
})

app.listen(4000, () =>
  console.log('Provider listening on http://localhost:4000')
)

/* util */
function sha256Hex (data: string) {
  return crypto.createHash('sha256').update(data).digest('hex')
}
```

#### browser-helper.js

```js
/**
 * Tiny helper that:
 *   1. hashes the request body
 *   2. asks the vending service for a PSAT
 *   3. calls the provider with ?sig=<psat>
 *
 * Config constants below ⬇
 */

const VENDING_URL   = 'https://edge.example.dev/delegate'
const PROVIDER_ORIG = 'https://api.example.dev'

/**
 * psatFetch('POST', '/v1/echo', { msg:'hello' })
 */
export async function psatFetch (method, path, bodyObj) {
  const bodyStr = JSON.stringify(bodyObj)
  const bodySha = await sha256Hex(bodyStr)

  /* 1. mint capability */
  const sig = await getSig({ m: method, p: path, bodySha })

  /* 2. call provider */
  const url = `${PROVIDER_ORIG}${path}?sig=${encodeURIComponent(sig)}`
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: bodyStr
  })
  if (!res.ok) throw new Error(`provider error ${res.status}`)
  return res.json()
}

/*———— helper fns ————*/
async function getSig(payload) {
  const res = await fetch(VENDING_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  if (!res.ok) throw new Error('PSAT vending failed')
  return (await res.json()).sig
}

async function sha256Hex (str) {
  const enc = new TextEncoder().encode(str)
  const digest = await crypto.subtle.digest('SHA-256', enc)
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, '0')).join('')
}
```

---

### 🔗 Wiring it up locally

Piece Command

* Edge worker npx wrangler dev src/examples/edge-vending-worker.ts --env dev
* Provider node src/examples/express-provider.ts (needs JWKS_URL env)
* Browser test In a local HTML/JS file: import { psatFetch } from './browser-helper.js'; psatFetch('POST','/v1/echo',{msg:'hi'}).then(console.log);

With the three example files you have a round-trip prototype: browser → edge vending → provider → browser, no credential exposure. Tweak paths, origins, and env vars to fit your dev setup, and you’re good to push them into the repo. 🛠️

---

## 🗺 Roadmap

Phase 0 Goal

01. Publish draft spec + reference Edge Worker & Express verifier
02. Add streaming-body support (chunked hashes) & DPoP key-binding
03. TypeScript SDK (psat-fetch) for easy browser integration
04. Submit IETF Internet-Draft, gather wider feedback

---

## 🤝 Contributing

 1. Fork → Feature branch → PR.
 2. If you’re proposing spec text, prefix the branch with spec/ and open a
Discussion first.
 3. Run npm run lint and npm test before pushing.
 4. See CONTRIBUTING.md for issue templates & coding style.

We follow the Contributor Covenant v2.1.

---

## 📄 License

 • Specification & docs – Creative Commons CC-BY-4.0
 • Source code – Apache 2.0

---

Made with ☕ and ideas from the web-dev community. Join the discussion in
GitHub Discussions or #psat on Mastodon/@Fediverse!
