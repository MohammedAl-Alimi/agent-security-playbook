# ⏱️ Rate Limiting & Abuse Prevention

Every expensive or mutating route gets a globally-consistent, identity-keyed, fail-closed limiter — in-memory counters on serverless are a limiter that does not exist.

## TL;DR — the rules

1. Never use an in-process Map/counter on serverless — use a global store (`@upstash/ratelimit` + Redis or equivalent).
2. Key limits on `userId ?? ip`; run both limiters on expensive endpoints.
3. Security-critical routes (auth, email, LLM, payments) FAIL CLOSED on limiter errors — Upstash's default is fail-open.
4. Rate limit Server Actions inside the action body — path-matched middleware/WAF rules never fire for them.
5. Tier your limits: strictest on auth endpoints, email sends, LLM calls, and payment mutations.
6. Layer platform (WAF rules, BotID/Turnstile) over app-level limits — neither replaces the other.
7. Mutating endpoints accept an `Idempotency-Key` deduped via a DB UNIQUE constraint.
8. Return 429 with a `Retry-After` header derived from the limiter's reset time.

## Rule 1 — Global store, never in-memory

**Why:** Serverless functions scale horizontally and reset per instance: an in-memory `Map` gives every cold start a fresh counter, so under real attack load the effective limit is infinite (AI-codegen failure mode #18 in the research corpus). All six surveyed "production-ready" starters ship zero enforced rate limits; next-forge ships an Upstash wrapper wired to zero routes.

```ts
// ❌ WRONG — resets on every cold start, per-instance, useless on Vercel/Lambda
const hits = new Map<string, number>();
export async function POST(req: Request) {
  const n = (hits.get(ip(req)) ?? 0) + 1;
  if (n > 10) return new Response("Too many", { status: 429 });
  hits.set(ip(req), n);
}

// ✅ RIGHT — lib/ratelimit.ts: one global Redis-backed limiter per route class
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

export const authLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "1 m"), // smooth, no window-boundary bursts
  analytics: true,
  prefix: "rl:auth",
});
```

Sliding window is the default choice (smooths boundary bursts); use token bucket when you want to allow short legitimate bursts against a steady refill (e.g., API clients). Fixed window is acceptable only for coarse platform rules.

**Verify:** `grep -rn 'new Map\|new Set' app/ src/ | grep -i 'limit\|throttle\|attempt'` → zero hits; load-test the deployed route: request N+1 within the window returns 429 even across instances.

## Rule 2 — Key on `userId ?? ip`, both for expensive routes

**Why:** IP-only keying blocks whole CGNAT/university networks while a logged-in attacker rotates IPs freely. Identity-first keying limits the actual actor; the IP limiter backstops anonymous abuse. Never key on a client-inventable header.

```ts
// ❌ WRONG — client controls this header entirely
const key = req.headers.get("x-forwarded-for") ?? "anon";

// ✅ RIGHT — authenticated: userId; anonymous: platform-derived IP
import { ipAddress } from "@vercel/functions";
const { userId } = await auth();
const key = userId ?? ipAddress(req) ?? "127.0.0.1";
const { success, reset } = await limiter.limit(key);
```

**Verify:** integration test — two sessions behind the same IP: user A exhausting their limit does not 429 user B; an anonymous flood from one IP does get 429.

## Rule 3 — Fail CLOSED on the routes that matter

**Why:** `@upstash/ratelimit` is fail-open by default: after a 5s Redis timeout it **allows** the request. For a product page that's correct; for login, checkout, email, or LLM routes it means "DDoS the Redis, then brute-force freely." Choose the fail mode explicitly per endpoint, in code.

```ts
// ❌ WRONG — Redis outage silently disables the login limiter
const { success } = await authLimiter.limit(key);
if (!success) return new Response("Too many", { status: 429 });

// ✅ RIGHT — limiter error on a critical route = deny
let success: boolean, reset: number;
try {
  ({ success, reset } = await authLimiter.limit(key));
} catch (err) {
  logger.error({ err, route: "login" }, "rate_limiter_unavailable");
  return new Response("Service unavailable", { status: 503 }); // fail closed
}
if (!success) return new Response("Too many requests", {
  status: 429,
  headers: { "Retry-After": String(Math.ceil((reset - Date.now()) / 1000)) },
});
```

**Verify:** unit test with a mocked Redis client that throws → login route returns 503, never 200; grep every auth/email/LLM/payment handler for a try/catch around `.limit(`.

## Rule 4 — Server Actions: limit inside the body

**Why:** Server Actions POST to the page's own URL, so path-matched middleware and WAF rules never fire for them. The limiter must be the first thing the action body does after auth.

```ts
// ✅ RIGHT — order: auth → limit → validate → work
export const sendInvite = authActionClient
  .inputSchema(InviteSchema)
  .action(async ({ parsedInput, ctx }) => {
    await assertLimit(emailLimiter, ctx.userId); // throws 429 — fail closed
    // ...work
  });
```

**Verify:** grep every `'use server'` file: a `.limit(`/`assertLimit(` call precedes any DB/email/LLM statement.

## Rule 5 — Tier limits by blast radius

**Why:** Credential stuffing hits auth endpoints; email abuse burns money and sender reputation (Resend caps teams at 10 req/s); LLM calls are unbounded consumption (OWASP LLM10); payment endpoints attract card-testing.

```ts
// ✅ RIGHT — per-class limiters with distinct prefixes
export const authLimiter    = mk(Ratelimit.slidingWindow(5,  "1 m"), "rl:auth");   // + lockout via your IdP
export const emailLimiter   = mk(Ratelimit.slidingWindow(10, "1 h"), "rl:email");  // per-user daily cap too
export const llmLimiter     = mk(Ratelimit.slidingWindow(20, "1 m"), "rl:llm");    // + daily token/$ budget BEFORE streaming
export const paymentLimiter = mk(Ratelimit.slidingWindow(10, "1 h"), "rl:pay");
```

Don't rebuild what your IdP ships: Clerk's Frontend API is already per-IP limited (sign-ups 5/10s) with account lockout at 100 failures/hour — your limiters cover the custom endpoints you wrote.

**Verify:** a route manifest maps every POST route/action to its limiter class; CI fails on unmapped mutating routes.

## Rule 6 — Layer platform protection over app limits

**Why:** Vercel WAF rate limiting uses fixed windows with **per-region** counters — a distributed attacker exceeds the configured limit — so it's the coarse outer wall, not the enforcement layer. BotID/Turnstile handle bots that any counter-based limiter can't distinguish from users.

```text
✅ RIGHT — layering, outermost first:
1. Vercel WAF rule (coarse ceiling, per-region caveat) — or your CDN/WAF equivalent
2. BotID: withBotId(nextConfig) + initBotId({protect}) + server-side checkBotId()
   (routes not registered in initBotId make checkBotId() fail; dev always isBot:false)
   — or Turnstile: server-side siteverify POST is the ONLY enforcement; tokens single-use, 300s
3. @upstash/ratelimit keyed userId ?? ip (the strict global cap)
4. DB idempotency keys (Rule 7)
Ship in observe mode (analytics: true, WAF Log action) for one traffic cycle, then enforce.
Escalate to CAPTCHA only after a limiter trips — friction is a response, not a default.
```

**Verify:** `checkBotId()` (or `siteverify`) result is branched on in the handler — grep confirms the call isn't fire-and-forget; WAF rule exists in the dashboard/IaC for auth paths.

## Rule 7 — Idempotency keys kill double-submit and replay

**Why:** Retries, double-clicks, and single-packet race attacks (PortSwigger: ~1ms window) turn one intended mutation into several. A DB UNIQUE constraint is the only atomic dedupe — never an in-memory Set. Pattern per Stripe/brandur.org: same key + same params replays the stored response; same key + different params → 422; concurrent duplicate → 409.

```ts
// ✅ RIGHT — claim the key atomically inside the side-effect transaction
const { rowCount } = await sql`
  INSERT INTO idempotency_keys (key, user_id, params_hash)
  VALUES (${key}, ${userId}, ${hash}) ON CONFLICT (key) DO NOTHING`;
if (rowCount === 0) return replayOrConflict(key, hash); // stored response / 422 / 409
```

A plain Postgres table with RLS suffices — no Redis needed.

**Verify:** integration test fires the same POST twice in parallel → exactly one side effect (one row, one email, one charge).

## Rule 8 — 429 with Retry-After

**Why:** Well-behaved clients back off only if told how long; ad-hoc 400/500 responses cause retry storms that amplify the load you're shedding.

```ts
// ✅ RIGHT
return new Response("Too many requests", {
  status: 429,
  headers: { "Retry-After": String(Math.ceil((reset - Date.now()) / 1000)) },
});
```

Log each trip as a structured `rate_limit_exceeded` event (key, route, requestId) — it's your credential-stuffing alarm.

**Verify:** curl the limit → response is status 429 AND has a numeric `Retry-After` header; log stream shows the structured event.

---

Related: [05 — Secrets & Env](05-secrets-and-env.md) (fail-closed env validation) · [13 — SSRF & LLM](13-ssrf-and-llm.md) (LLM spend caps).
