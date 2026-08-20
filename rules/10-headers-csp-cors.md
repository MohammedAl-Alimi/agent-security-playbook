# 🧱 Headers, CSP & CORS

Ship the full security-header suite from day one, treat CORS as an exact-match allowlist, and give every cookie-authenticated mutation explicit CSRF protection — then pin it all with a CI assertion.

## TL;DR — the rules

1. Ship a nonce-based CSP with `'strict-dynamic'` (the official Next.js pattern); never set `contentSecurityPolicy: false`.
2. Set `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` yourself — platforms don't fully set it on custom domains.
3. Block framing with CSP `frame-ancestors 'none'`, not just `X-Frame-Options`.
4. Set `X-Content-Type-Options: nosniff`, a strict `Referrer-Policy`, and a minimal deny-by-default `Permissions-Policy`.
5. CORS: exact-origin allowlist from env; never `*` (or a reflected Origin) with credentials; answer preflight explicitly.
6. Cookies: `httpOnly` + `secure` + `sameSite: 'lax'` minimum, `__Host-` prefix.
7. CSRF: Server Actions have built-in Origin/Host checks; cookie-authenticated mutating Route Handlers need their own Origin check — and never mutate on GET.
8. Assert the headers in CI — a header that isn't tested will be silently deleted by a future session.

## Rule 1 — Nonce-based CSP with strict-dynamic

The boilerplate survey found **zero of six "production-ready" starters ship a CSP** — and next-forge explicitly sets `contentSecurityPolicy: false`. CSP is the backstop for the XSS class AI code fails 86% of the time (Veracode). The official Next.js guide pattern: middleware generates a per-request nonce.

```ts
// ❌ WRONG — no CSP, or the "make it work" special: script-src 'unsafe-inline' *

// ✅ RIGHT — middleware.ts (per nextjs.org/docs/app/guides/content-security-policy)
const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
const csp = [
  `default-src 'self'`,
  `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'` +
    (process.env.NODE_ENV === 'development' ? ` 'unsafe-eval'` : ''),
  `style-src 'self' 'nonce-${nonce}'`,
  `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`,
  `frame-ancestors 'none'`, `upgrade-insecure-requests`,
].join('; ');
requestHeaders.set('x-nonce', nonce);
response.headers.set('Content-Security-Policy', csp);
```

Caveat: nonces force full dynamic rendering (incompatible with ISR/PPR). If you need static rendering, use a strict allowlist CSP or experimental SRI — **never delete the CSP to keep ISR**. Diff against `vercel/next.js` `examples/with-strict-csp` instead of generating from memory.

**Verify:** CI fetches one page and asserts `Content-Security-Policy` contains `nonce-` and `strict-dynamic` and lacks `unsafe-inline` in `script-src`.

## Rule 2 — HSTS, nosniff, referrer, permissions

Verified platform asymmetry: `*.vercel.app` gets the full HSTS header automatically; **custom domains get only `max-age`** — `includeSubDomains` and `preload` are your job. The rest of the suite is one config block; `@nosecone/next` gives hardened defaults (including the COOP/CORP/COEP trio and `X-XSS-Protection: 0`) in one call.

```ts
// ✅ RIGHT — next.config.ts headers() (or @nosecone/next)
headers: [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },   // stops MIME-sniffing uploads into scripts
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
]
```

Framing: `frame-ancestors 'none'` in the CSP (Rule 1) is the modern control — `X-Frame-Options` can't express allowlists and is ignored when both are present; keep it only as a legacy fallback. Permissions-Policy is deny-by-default: start with everything off, enable per feature.

**Verify:** `curl -sI https://$HOST | grep -Ei 'strict-transport|nosniff|referrer-policy|permissions-policy'` → all four present, HSTS includes `preload`.

## Rule 3 — CORS: exact allowlist, never wildcard-with-credentials

Wildcard/reflected CORS is a recurring AI-codegen bug — even full-stack-fastapi-template (the best-configured survey starter) pins the origin but wildcards methods/headers **with credentials on**. The anti-pattern to ban: `res.headers.set('Access-Control-Allow-Origin', origin || '*')` — reflecting the request Origin is `*` with extra steps, and with `Allow-Credentials: true` it hands any website your users' authenticated API.

```ts
// ❌ WRONG — reflected origin + credentials = any site reads your API as the victim
const origin = req.headers.get('origin');
res.headers.set('Access-Control-Allow-Origin', origin ?? '*');
res.headers.set('Access-Control-Allow-Credentials', 'true');

// ✅ RIGHT — exact-match allowlist from env, explicit preflight handler
const ALLOWED = new Set(env.CORS_ORIGINS.split(','));   // e.g. https://app.example.com
function corsHeaders(req: Request) {
  const origin = req.headers.get('origin');
  if (!origin || !ALLOWED.has(origin)) return null;      // no header = browser blocks
  return { 'Access-Control-Allow-Origin': origin, 'Vary': 'Origin',
           'Access-Control-Allow-Credentials': 'true',
           'Access-Control-Allow-Methods': 'GET,POST', 'Access-Control-Allow-Headers': 'content-type' };
}
export async function OPTIONS(req: Request) {
  const h = corsHeaders(req);
  return new Response(null, { status: h ? 204 : 403, headers: h ?? {} });
}
```

```python
# ✅ RIGHT — FastAPI: enumerate everything, never ["*"] with credentials
app.add_middleware(CORSMiddleware, allow_origins=[settings.FRONTEND_HOST],
                   allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["content-type"])
```

Same-origin apps need no CORS at all — adding it "to fix a fetch error" is usually masking a misconfigured URL.

**Verify:** test sends `Origin: https://evil.example` to a CORS route → response has no `Access-Control-Allow-Origin`; grep for `Allow-Origin.*\*` and `allow_origins=\["\*"\]` → zero where credentials are enabled.

## Rule 4 — Cookies: httpOnly, secure, sameSite, __Host-

Custom session/state cookies without flags are readable by any XSS and sent cross-site. `sameSite: 'lax'` is the CSRF floor; `__Host-` prefix guarantees `secure`, no `Domain`, and `path=/` at the browser level.

```ts
// ❌ WRONG
cookies().set('session', token);

// ✅ RIGHT
cookies().set('__Host-session', token, {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 60 * 60 * 24,
});
```

**Verify:** grep `cookies().set`/`Set-Cookie` call sites for missing `httpOnly`/`sameSite` → zero; a response-header test asserts the flags on the login flow.

## Rule 5 — CSRF: Server Actions are covered, Route Handlers are not

Verified split: Next.js Server Actions ship built-in Origin-vs-Host checking (configure `serverActions.allowedOrigins` behind proxies). **Route Handlers have zero CSRF protection** — a cookie-authenticated POST handler is callable from any site the moment `sameSite` alone isn't enough (subdomains, top-level navigations, legacy browsers).

```ts
// ❌ WRONG — cookie-authed mutation, no origin check; also: never mutate on GET
export async function POST(req: Request) { await deleteAccount(await getSession(req)); }

// ✅ RIGHT — explicit Origin allowlist before the auth/session read
export async function POST(req: Request) {
  const origin = req.headers.get('origin');
  if (!origin || !ALLOWED.has(origin)) return new Response('Forbidden', { status: 403 });
  await deleteAccount(await getSession(req));
}
```

Webhooks are the exception: Origin-exempt but signature-verified over the raw body ([08 — Webhooks](./08-webhooks.md)). Bearer-token APIs (no cookies) don't need CSRF checks — CSRF rides on ambient credentials.

**Verify:** test POSTs to each cookie-authenticated handler with `Origin: https://evil.example` and a valid session cookie → 403; grep route handlers for mutations inside `export async function GET` → zero.

## Rule 6 — Headers are enforced by CI, not memory

A future session (human or AI) debugging a blocked script will "fix" it by weakening the CSP — threat-model row #15. The only durable defense is a test that turns the weakening into a red build.

```ts
// ✅ RIGHT — e2e/headers.spec.ts (Playwright, runs against a production build/preview)
const EXPECT: Record<string, RegExp> = {
  'content-security-policy': /strict-dynamic/,
  'strict-transport-security': /includeSubDomains; preload/,
  'x-content-type-options': /^nosniff$/,
  'referrer-policy': /strict-origin/,
  'permissions-policy': /camera=\(\)/,
};
for (const url of ['/', '/api/health']) {
  test(`headers on ${url}`, async ({ request }) => {
    const res = await request.get(url);
    for (const [k, re] of Object.entries(EXPECT))
      expect(res.headers()[k], k).toMatch(re);
  });
}
```

Preview deployments keep Standard Protection; CI authenticates with the Protection Bypass for Automation header and the OPTIONS Allowlist handles preflights — never disable protection to make tests pass.

**Verify:** the spec above runs on every PR against a preview deploy; deleting any header fails CI.

---

Previous: [09 — Logging & Errors](./09-logging-and-errors.md) · Next: [12 — Payments & Billing](./12-payments.md)
