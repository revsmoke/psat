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