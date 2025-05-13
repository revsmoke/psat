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

Under the hood:
 1. Edge Worker (examples/edge-vending-worker.ts) checks your cookie/session,
generates a PSAT for POST /v1/echo, and responds with
{"sig":"<jwt>"}.
 2. Browser helper (examples/browser-helper.js) appends the token to the real
provider URL and performs the fetch.
 3. Provider verifier (examples/express-provider.ts) validates the signature
& claims before echoing the payload.

⸻

🔐 Security in One Slide
 • 1–5 minute TTL (exp)
 • Method, path and SHA-256(body) locked in claims
 • Optional origin ties token to a specific web origin
 • Ed25519 signatures; public keys served via JWKS
 • Full analysis in Appendix A of the spec

⸻

🗺 Roadmap

Phase Goal
0.1 Publish draft spec + reference Edge Worker & Express verifier
0.2 Add streaming-body support (chunked hashes) & DPoP key-binding
0.3 TypeScript SDK (psat-fetch) for easy browser integration
0.4 Submit IETF Internet-Draft, gather wider feedback


⸻

🤝 Contributing
 1. Fork → Feature branch → PR.
 2. If you’re proposing spec text, prefix the branch with spec/ and open a
Discussion first.
 3. Run npm run lint and npm test before pushing.
 4. See CONTRIBUTING.md for issue templates & coding style.

We follow the Contributor Covenant v2.1.

⸻

📄 License
 • Specification & docs – Creative Commons CC-BY-4.0
 • Source code – Apache 2.0

⸻

Made with ☕ and ideas from the web-dev community. Join the discussion in
GitHub Discussions or #psat on Mastodon/@Fediverse!

