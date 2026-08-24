# 🔑 Authentication

Verify who is calling in **every** entry point — not just at the front door. Middleware-only auth is the single most bypassed pattern in AI-generated apps.

## TL;DR — the rules

1. Every Route Handler, Server Action, and data-layer function performs its own auth check; middleware is never the authorization boundary.
2. Middleware does redirect UX only; pin `next >= 15.2.3` (or `>= 14.2.25`) and `@clerk/nextjs >= 6.39.2` (or `>= 7.2.1`) in CI.
3. Treat every Server Action as a public POST endpoint: all mutations go through one shared auth + validation wrapper.
4. Store sessions in `httpOnly; secure; sameSite` cookies — never in localStorage or any JS-readable storage.
5. Return identical errors and comparable timing on login and password-reset whether or not the account exists.
6. Ship MFA hooks from day one: step-up verification on sensitive actions, backup codes stored hashed.
7. Treat RSC flight payloads as attacker-controlled input; framework security patches (React2Shell class) are same-week deploys, enforced by a recurring CI version gate.
8. No default or seeded credentials anywhere: no `admin/admin`, no shared demo password in prod, no unchanged service defaults — seeded accounts get per-environment random secrets or don't exist in prod.

## Rule 1 — Auth check in every handler, action, and DAL function

**Why:** CVE-2025-29927 (CVSS 9.1) let attackers skip Next.js middleware entirely — including `clerkMiddleware` — with one spoofed `x-middleware-subrequest` header. Clerk's own `createRouteMatcher`-only gating was bypassed (GHSA-vqx2-fgx2-5wq9). All six major "production-ready" starters surveyed in the research corpus ship middleware-only auth; two even exclude `/api` from the matcher. The durable lesson: auth lives in a Data Access Layer, re-checked at every entry point.

```ts
// ❌ WRONG — middleware is the only check; one header bypasses it
// middleware.ts
export default clerkMiddleware(); // protects NOTHING by default
// app/api/invoices/route.ts
export async function GET() {
  return Response.json(await db.invoice.findMany()); // no check at all
}

// ✅ RIGHT — the handler (or the DAL function it calls) checks itself
// app/api/invoices/route.ts
import { auth } from '@clerk/nextjs/server';
export async function GET() {
  const { userId } = await auth();
  if (!userId) return new Response('Unauthorized', { status: 401 });
  return Response.json(await getInvoicesFor(userId)); // DAL scopes by caller
}
```

Python/FastAPI: same principle via dependency injection — every route declares `user: User = Depends(get_current_user)`; there is no "global middleware protects everything" shortcut worth trusting.

Fail closed: a thrown error inside the auth path returns 401/500 — never falls through to the data fetch.

**Verify:** grep every file under `app/api/**` and every `'use server'` file for an `auth()` / `authActionClient` / `get_current_user` reference — zero misses; then `curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"` with no session against a protected route → still 401.

## Rule 2 — Middleware is redirect UX only; pin patched versions

**Why:** Middleware is a convenience layer for redirecting logged-out users to `/sign-in`. It runs before caching, can be skipped (CVE-2025-29927 on `next < 14.2.25 / < 15.2.3`), and — on Clerk — protects nothing unless you call `auth.protect()`. Auth checks in `layout.tsx` are equally unsafe: layouts don't re-render on client-side navigation.

```ts
// ❌ WRONG — treating a redirect as a security control
export default clerkMiddleware(async (auth, req) => {
  if (isProtectedRoute(req)) await auth.protect(); // fine as UX…
}); // …but nothing else checks, so a bypass = full access

// ✅ RIGHT — middleware redirects; handlers enforce (Rule 1); versions pinned
// package.json: "next": ">=15.2.3", "@clerk/nextjs": ">=6.39.2"
```

Self-hosted (not on Vercel, which strips the header)? Also strip `x-middleware-subrequest` at your proxy.

**Verify:** CI script reads the lockfile and fails on `next < 15.2.3` (or `< 14.2.25`; `>= 15.4.7`/`14.2.32` if you also want the CVE-2025-57822 SSRF fix) or `@clerk/nextjs < 6.39.2`; grep `app/**/layout.tsx` for `auth(` / `redirect(` used as gate → zero hits.

## Rule 3 — Server Actions are public endpoints

**Why:** A `'use server'` function compiles to an unauthenticated public POST endpoint at the page's own URL — callable with `curl`, invisible to path-matched middleware and WAF rules (per nextjs.org data-security guide). AI-generated code reliably treats them as internal helpers.

```ts
// ❌ WRONG — bare exported action, no auth, raw args
'use server';
export async function deleteProject(id: string) {
  await db.project.delete({ where: { id } });
}

// ✅ RIGHT — one shared client does auth + schema before any body runs
// lib/safe-action.ts
import { createSafeActionClient } from 'next-safe-action';
export const authActionClient = createSafeActionClient().use(async ({ next }) => {
  const { userId, orgId } = await auth();
  if (!userId) throw new Error('Unauthorized');
  return next({ ctx: { userId, orgId } });
});
// app/projects/actions.ts
export const deleteProject = authActionClient
  .inputSchema(z.strictObject({ id: z.uuid() }))
  .action(async ({ parsedInput, ctx }) => {
    await db.project.delete({ where: { id: parsedInput.id, ownerId: ctx.userId } });
  });
```

**Verify:** grep for `'use server'` files that do not import the shared `authActionClient` → zero; invoke one action directly with no session cookie → denied.

## Rule 4 — Sessions live in httpOnly cookies, not localStorage

**Why:** Any token readable by JavaScript is exfiltrated by the first XSS — and Veracode's 2025 report measured LLMs failing XSS defenses in 86% of tasks, so assume XSS will land. `httpOnly` cookies are invisible to scripts; `secure` + `sameSite` + `__Host-` prefix close the transport and CSRF gaps. See [hashing & tokens](06-hashing-and-tokens.md) for what goes *inside* the cookie.

```ts
// ❌ WRONG — token available to every injected script
localStorage.setItem('access_token', jwt);

// ✅ RIGHT — server sets an httpOnly cookie; JS never touches the token
cookies().set('__Host-session', sessionToken, {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/',
  maxAge: 60 * 60 * 24, // ≤ 24h
});
```

Managed SDKs (Clerk, Supabase Auth with `@supabase/ssr`) already do this — don't re-implement client-side token storage next to them.

**Verify:** grep client code for `localStorage.setItem`/`sessionStorage.setItem` with token/JWT-like values → zero; response `Set-Cookie` header contains `HttpOnly; Secure; SameSite`.

## Rule 5 — No account enumeration: uniform errors, uniform timing

**Why:** "No account with that email" on login or reset gives attackers a free user directory for credential stuffing and phishing (OWASP Authentication Cheat Sheet). Timing leaks the same fact: returning early when the user is missing skips the slow hash and is measurable.

```ts
// ❌ WRONG — different message and different response time per branch
const user = await findUser(email);
if (!user) return err('No account with that email');       // fast + specific
if (!(await argon2.verify(user.hash, password))) return err('Wrong password');

// ✅ RIGHT — one message, hash work on both branches
const user = await findUser(email);
const hash = user?.passwordHash ?? DUMMY_ARGON2_HASH; // verify against a real dummy hash
const ok = await argon2.verify(hash, password);
if (!user || !ok) return err('Invalid email or password'); // always this, always ~same time
// Password reset: ALWAYS respond "If an account exists, we sent an email."
```

Sign-up leaks too: confirm via email ("if this address is new you'll get a verification link") rather than an inline "email already registered". Managed providers handle much of this — don't undo it with custom wrapper messages.

**Verify:** integration test posts login + reset for an existing and a non-existing email → response bodies and status codes are byte-identical; median response-time delta < 50ms across 20 runs.

## Rule 6 — MFA hooks from day one

**Why:** Password-only auth falls to credential stuffing regardless of hash quality; ASVS 5.0 (V6/V8) treats MFA and re-authentication as baseline for anything above trivial risk. Retrofitting MFA into a session model that never planned for it is a rewrite.

```ts
// ❌ WRONG — session is a boolean; no way to demand a second factor later
if (session) allowEverything();

// ✅ RIGHT — session records assurance level; sensitive actions step up
const { userId, sessionClaims } = await auth();
if (SENSITIVE_ACTIONS.has(action) && sessionClaims?.mfaVerifiedAt == null) {
  return { error: 'mfa_required' }; // client routes to TOTP/WebAuthn challenge
}
```

Use the provider's built-ins where they exist (Clerk: TOTP/SMS/backup codes; Supabase Auth: MFA API). If custom: TOTP secrets encrypted at rest, backup codes stored **hashed** like passwords — see [hashing & tokens](06-hashing-and-tokens.md). Never accept an MFA flag from the request body ([authorization](02-authorization.md), mass assignment).

**Verify:** test invokes a sensitive action with a valid but non-MFA session → denied with `mfa_required`; grep input schemas for `mfa|verified` fields accepted from clients → zero.

## Rule 7 — RSC payloads are attacker input; framework patches deploy same week

**Why:** React2Shell (CVE-2025-55182, CVSS 10.0) was unauthenticated RCE in React Server Components' flight deserialization — a default `create-next-app` build was vulnerable via `react-server-dom-*`, paired with Next.js CVE-2025-66478, and exploited in the wild within days of the December 2025 disclosure. The durable lessons: the RSC wire format is attacker-controlled serialized input your server deserializes *before any of your code runs*, so no handler-level check compensates — and version pinning (Rule 2) only protects you if security releases actually reach production.

```jsonc
// ❌ WRONG — floating on whatever the scaffold resolved; patch never scheduled
"react": "19.0.0", "react-dom": "19.0.0"          // vulnerable line

// ✅ RIGHT — at or above the fixed release for each line, deployed the week it shipped
"react": ">=19.2.1", "react-dom": ">=19.2.1"      // fixed floors: 19.0.1 / 19.1.2 / 19.2.1
// react-server-dom-webpack|turbopack|parcel: same floors; next: CVE-2025-66478 patch
```

Standing policy: a framework security release (React, Next.js, auth SDK) is a same-week production deploy, and a **recurring** CI job re-runs the lockfile gate ([15 — Self-Verification](./15-testing-verification.md) Rule 7) so an advisory published between PRs still turns the pipeline red. Vercel's WAF rules for React2Shell were a stopgap only — upgrade regardless.

**Verify:** lockfile shows react/react-dom/react-server-dom-* at ≥ 19.0.1/19.1.2/19.2.1 per line and a patched Next.js; the version-gate workflow has a `schedule:` trigger, not just `pull_request`.

## Rule 8 — No default or seeded credentials

**Why:** AI-generated seed scripts love `admin@example.com / password123`, and those accounts ship to production because nothing fails when they do. Default credentials are a top breach entry point across every industry report — and the vibe-coded variant is worse, because the same well-known seed password appears in thousands of generated apps and in the repo itself. The same applies to infrastructure defaults: a Postgres/Redis/Grafana container left on its default password is an open door.

```ts
// ❌ WRONG — fixed credentials in a seed script that can run anywhere
await createUser({ email: 'admin@example.com', password: 'admin123', role: 'admin' });

// ✅ RIGHT — seeding is dev-only and secrets are generated, never written down
if (env.ENV === 'production') throw new Error('seed script must not run in prod');
const password = crypto.randomBytes(24).toString('base64url');   // printed once, or use invite flow
await createUser({ email: 'admin@example.com', password, role: 'admin' });
```

Prod admin access comes from a real invite/signup flow (with MFA, Rule 6) — never a pre-created account. Self-hosted services (DBs, dashboards, queues) get their default credentials changed at provision time, enforced by the boot assertion pattern from [deployment](25-deployment-infrastructure.md).

**Verify:** grep seeds/fixtures/docker-compose for hardcoded passwords → only dev-guarded, generated ones; a prod smoke test attempts login with the seed email + known seed password → rejected; boot assertion fails prod if a seeded demo account exists with a password set.
