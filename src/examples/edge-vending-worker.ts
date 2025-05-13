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