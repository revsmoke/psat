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