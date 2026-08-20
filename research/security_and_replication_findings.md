# Security & Replication Findings

**The research foundation for the security playbook.** Stack: Next.js (App Router) on Vercel + Supabase + Clerk + Resend + FastAPI services, with LLM-calling features. Consumed by future AI coding sessions. Every claim below was verified against primary sources; every URL was live at research time (2026-08).

---

## 1. Executive Summary — The 10 Non-Negotiables

1. **RLS on every table, in the same migration that creates it.** A Supabase table without RLS is world-readable/writable via the anon key shipped in every browser bundle. This is the single most catastrophic vibe-coding defect (CVE-2025-48757: 170+ breached Lovable apps). CI must run `tests.rls_enabled('public')`.
2. **Middleware is never the authorization boundary.** CVE-2025-29927 (CVSS 9.1) bypassed Next.js middleware — including `clerkMiddleware` — with one spoofed header. Every Server Action, Route Handler, and DAL function calls `await auth()` itself.
3. **Every query that takes an object ID also filters by the caller's identity.** IDOR/BOLA is OWASP API #1 and the most common vibe-coded vulnerability. Authentication is not authorization.
4. **Every external input is parsed through a strict schema before use** — `z.strictObject()` (Zod v4) / Pydantic `ConfigDict(extra='forbid')` — including searchParams, route params, headers, webhook payloads, and LLM output. Never spread raw input into a DB write.
5. **Secrets are structurally quarantined.** t3-env validates env at build time; `SUPABASE_SERVICE_ROLE_KEY` lives only in `import 'server-only'` modules; nothing secret ever carries `NEXT_PUBLIC_`.
6. **Every webhook verifies its signature over the raw body before parsing, and fails closed** — a missing signing secret is a boot failure, never a silent 200 (the verified next-forge fail-open bug).
7. **Rate limit and bot-protect every expensive or mutating route** (auth-adjacent, email, LLM, payments) with `@upstash/ratelimit` keyed on `userId ?? ip`, failing CLOSED — its default is fail-open after a 5s timeout.
8. **Fail closed everywhere.** A catch block around auth/validation denies; clients get a generic message + request ID; security events (`authn_login_fail`, `authz_fail`, `rate_limit_exceeded`) are logged as structured JSON with PII redacted.
9. **Supply chain is a first-class attack surface** (A03:2025). No dependency installed without registry verification (slopsquatting), lockfiles committed, GitHub Actions SHA-pinned, gitleaks + TruffleHog in pre-commit and CI.
10. **Negative tests and machine gates, not vigilance.** AI-generated code fails by *omission*, and developers using AI assistants rate their insecure code as *more* secure (Stanford). Ship the cross-tenant/401/replay/tamper test suite and CI gates (Semgrep, splinter, pgTAP) with every app.

---

## 2. The AI-Codegen Threat Model

**Why this exists:** Veracode's 2025 GenAI report (100+ LLMs, 80 tasks) found AI introduces vulnerabilities in **45% of coding tasks** (~2.74x human baseline), failing XSS 86% and log injection 88% of the time — and newer models improved at syntax, **not** security. Pearce et al. (IEEE S&P 2022) measured ~40% of Copilot programs vulnerable. GitGuardian: AI-assisted commits leak secrets at **>2x the human rate** (3.2% vs 1.5%; 6.4% with Copilot). Escape.tech scanned 5,600 vibe-coded apps and found 2,000+ vulnerabilities with passive DAST alone; Symbiotic found flaws in 98% of 1,072.

**The core pattern:** AI code fails on **omission**, not bad syntax. Models rarely write bad crypto; they silently omit the RLS policy, the auth check, the rate limiter, the signature verification, the DB constraint — because the feature still "works" in the happy-path demo. Guardrails must therefore be **default-on infrastructure** (build failures, CI gates, mandatory wrappers), never per-feature reminders.

| # | Documented failure mode | Evidence | Guardrail |
|---|---|---|---|
| 1 | Tables created without RLS — world-readable via anon key | CVE-2025-48757 (Lovable, 170+ apps); Escape.tech scan | RLS + policies in the same migration; `tests.rls_enabled('public')` in CI; splinter lints build-breaking |
| 2 | Middleware-only auth, bypassed wholesale | CVE-2025-29927 (`x-middleware-subrequest`); Clerk GHSA-vqx2-fgx2-5wq9 | Auth in every handler/action/DAL; pin `next>=15.2.3`/`>=14.2.25`, `@clerk/nextjs>=6.39.2` |
| 3 | Assuming `clerkMiddleware()` protects routes — it protects **nothing** by default | clerk.com/docs/reference/nextjs/clerk-middleware | Explicit `auth()`/`auth.protect()` per resource; middleware = redirect UX only |
| 4 | Server Actions treated as internal — they are public POST endpoints | nextjs.org/docs/app/guides/data-security | All mutations through one `authActionClient` (next-safe-action): auth + Zod before any body runs |
| 5 | IDOR: "is logged in" checked, "owns row :id" never | OWASP API1:2023 BOLA | Ownership predicate in the WHERE clause (scoped query, 404 on zero rows) + RLS backstop |
| 6 | Mass assignment / client-supplied `role`, `userId`, `orgId`, `amount` | Zod default strips silently; `.passthrough()` passes `admin:true` | `z.strictObject()`; identity fields derived from `auth()`, never accepted from input |
| 7 | Webhook handlers `JSON.parse` with no signature check | Universal in generated Clerk/Stripe/Resend handlers | `verifyWebhook()` / `constructEvent(raw)` first; 400 on failure; discriminated-union parse after |
| 8 | Fail-open guards: missing env var silently disables protection | next-forge: `if (!arcjetKey) return;` and Stripe webhook returning 200 "Not configured" | Boot-time env validation; missing security env = build/boot failure, 5xx from route |
| 9 | Secrets hardcoded or `NEXT_PUBLIC_`-prefixed to "make the fetch work" | GitGuardian 2026; EnrichLead shutdown | t3-env server/client split (build error); gitleaks pre-commit + CI; GitHub push protection |
| 10 | Slopsquatting: hallucinated package names installed on the model's word | USENIX '25: 5.2–21.7% hallucination rate; arXiv 2605.17062 | Verify on npmjs.com/PyPI (repo + downloads) before install; lockfile-only CI installs |
| 11 | Read-check-then-write races (credits, coupons, quotas) | PortSwigger single-packet attack (~1ms window) | Single atomic `UPDATE ... WHERE balance >= $x RETURNING`; UNIQUE constraints + ON CONFLICT |
| 12 | Payment fulfillment from a forgeable `?success=true` redirect | EnrichLead paywall bypassed from browser console in 72h | Webhook-driven idempotent fulfillment; re-fetch session from Stripe; `payment_status` check |
| 13 | SSRF: `fetch(req.body.url)` with zero validation; agent fetch tools trusting model URLs | CVE-2025-57822 (Next.js), CVE-2026-8768 (AI SDK), Pydantic AI CVE chain | Single named validator: scheme allowlist, resolve-then-pin IP, redirects off, metadata denylist |
| 14 | LLM output rendered/executed as trusted (`dangerouslySetInnerHTML`, `JSON.parse as T`) | OWASP LLM05/LLM01 | Schema-validated structured output (`generateObject`/instructor); render as text/sanitized markdown |
| 15 | Security-weakening "fixes": `USING (true)`, disable RLS, CORS `*`, comment out auth | Recurring AI debugging behavior | Hard rule: permission-widening diffs require explicit human approval — fix the policy, not remove it |
| 16 | Errors leak internals (Postgres text, stacks) or are swallowed fail-open | A10:2025 | Mask-by-default (`handleServerError` allowlist); generic message + digest/requestId to client |
| 17 | Coercion footguns: `z.coerce.boolean().parse('false') === true`; empty string → 0 | Verified on zod 4.4.3; issues #3924/#5501 | Ban `z.coerce.boolean()`; use `z.stringbool()`; non-empty guard before `coerce.number()` |
| 18 | In-memory Map rate limiters on serverless — infinite limit under real load | Per-instance counters reset on cold start | `@upstash/ratelimit` (global Redis counter); never in-process state on Vercel |
| 19 | Public storage buckets, client-controlled paths, no content validation | Supabase storage docs; SVG stored-XSS | Private buckets + storage.objects policies; server-generated `${userId}/${uuid}.${ext}` paths; sharp re-encode |
| 20 | False confidence: AI-assisted developers write worse code and trust it more | Perry et al., Stanford | Every rule in §5 is phrased as a machine-testable check, not a review guideline |

---

## 3. Per-Dimension Findings

### 3.1 OWASP Core (2025 re-keying)

- **OWASP Top 10:2025 is current** (owasp.org/Top10/2025/): A01 Broken Access Control (now absorbs SSRF), A02 Security Misconfiguration, A03 **Software Supply Chain Failures (new)**, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software/Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 **Mishandling of Exceptional Conditions (new)**. Key playbook sections to A01–A10:2025 IDs.
- **ASVS 5.0.0** (May 2025, github.com/OWASP/ASVS): 17 chapters, ~350 requirements, machine-parseable CSV. Directly relevant: V9 Self-Contained Tokens, V10 OAuth/OIDC (Clerk/Supabase JWTs), V3 Web Frontend, V8 Authorization, V2 Validation.
- **Load-bearing cheat sheets** (cheatsheetseries.owasp.org): Authorization, Input Validation, SQL Injection Prevention, Logging + Logging Vocabulary (`authn_login_success`, `authz_fail`), REST Security, Secrets Management, Mass Assignment, File Upload, HTTP Headers/CSP, SSRF Prevention, NodeJS. New and AI-relevant: **LLM Prompt Injection Prevention, AI Agent Security, Secure AI Model Ops**.
- **OWASP LLM Top 10 2025**: for apps that call LLMs, the load-bearing four are LLM01 (prompt injection — retrieved/user content is data, not instructions), LLM05 (improper output handling), LLM06 (excessive agency — least-privilege tools), LLM10 (unbounded consumption — spend caps).
- No FastAPI-specific OWASP sheet exists (DRF sheet is closest Python analog) — noted gap, not invented.

**Exemplars:** [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) (32.9k★, extract sheets verbatim into rules), [OWASP/ASVS](https://github.com/OWASP/ASVS) (vendor the L1/L2 CSV as a checklist), [OWASP/Top10](https://github.com/owasp/top10) (category IDs + CWE mappings).

**Baselines omit:** everything in §2 rows 1–9; boilerplates target 2021 categories and have no supply-chain or exceptional-conditions posture at all.

### 3.2 Input Validation

- **Zod v4 (4.4.3) semantics, verified by execution:** default `z.object()` *strips* unknown keys (safe-ish but silent); `.passthrough()`/`z.looseObject()` passes `admin:true` through — the #1 mass-assignment footgun when spread into an update. `z.strictObject()` rejects loudly → the correct posture for inbound payloads. `.strict()`/`.email()` are deprecated legacy → `z.strictObject()`, top-level `z.email()`/`z.uuid()`/`z.url()`. `.default()` now short-circuits without validating (use `.prefault()` for v3 behavior). Codemod: `npx zod-v3-to-v4`.
- **Coercion footguns:** `z.coerce.boolean().parse('false')` → `true`; `z.coerce.number().parse('')` → `0`. Only `z.stringbool()` parses `'false'/'0'` correctly. FormData needs `zod-form-data` or `z.string().min(1).pipe(z.coerce.number())`.
- **next-safe-action v8** (Standard Schema v1) makes validation structurally unavoidable: shared `actionClient.use(authMiddleware).inputSchema(schema)` — raw-args actions don't typecheck.
- **t3-env** (`@t3-oss/env-nextjs` 0.13.11): `createEnv({server, client, runtimeEnv})` imported in `next.config.ts` fails the *build* on missing/invalid env; server vars throw if touched client-side. Footgun: `SKIP_ENV_VALIDATION` disables everything — never set in production.
- **Pydantic v2:** default is lax coercion + `extra='ignore'`. Body models get `ConfigDict(extra='forbid')` (+ `strict=True` for internal DTOs); keep lax for query/path params (they arrive as strings). Every route declares `response_model=`. Boot-time env via pydantic-settings `BaseSettings`.
- **Polymorphic payloads** = discriminated unions (`z.discriminatedUnion('type', [...])` / `Field(discriminator='type')`), never one schema of optionals.
- **LLM output is untrusted input:** AI SDK `generateObject`/`streamObject` with a Zod schema (+ `.max()`, enums, URL host allowlists); Python: `instructor` `response_model=`. Schema conformance ≠ content safety.
- **One schema module:** dubinc/dub keeps 40+ per-resource schemas in `apps/web/lib/zod/schemas/` shared by routes, actions, forms, and OpenAPI.

**Exemplars:** [dubinc/dub](https://github.com/dubinc/dub) (24.5k★ centralized schemas), [t3-oss/t3-env](https://github.com/t3-oss/t3-env), [next-safe-action](https://github.com/next-safe-action/next-safe-action), [vercel/next-forge](https://github.com/vercel/next-forge) (composable per-package env `keys()` merged via `createEnv({extends})`), [567-labs/instructor](https://github.com/567-labs/instructor) (13.8k★), [colinhacks/zod](https://github.com/colinhacks/zod) (v4 changelog is the authoritative footgun record).

**Baselines omit:** any Server Action validation (TypeScript types are erased at runtime); boot-time env validation; rejection of client-supplied identity fields; duplicated drifting client/server schemas.

### 3.3 Authorization & RBAC

- **CVE-2025-29927:** `x-middleware-subrequest: middleware:middleware:...` skipped middleware entirely on Next.js <12.3.5/<13.5.9/<14.2.25/<15.2.3. Vercel-hosted apps were shielded (platform strips the header); self-hosted must strip at the proxy. Durable lesson: auth lives in a **Data Access Layer** (nextjs.org/docs/app/guides/data-security).
- **Clerk sharp edges (verified):** server-side `has({permission})` works only with *custom* permissions; all org checks return false with no Active Organization; **never place auth checks in layout.tsx** (doesn't re-render on navigation); `<Protect>`/`<Show>` hide UI only — data stays fetchable. Declare a global `ClerkAuthorization` interface for compile-time role-string checking. Clerk deprecates `createRouteMatcher`-only gating (GHSA-vqx2-fgx2-5wq9 bypassed it; patched in `@clerk/nextjs` 6.39.2/7.2.1).
- **BOLA prevention = scoped queries, not fetch-then-check:** `WHERE id = $1 AND org_id = $2`, 404 on zero rows. UUIDs are defense-in-depth only.
- **Multi-tenancy that survives both app bugs and RLS mistakes:** `org_id NOT NULL` on every tenant table; RLS USING + WITH CHECK against the JWT org claim; app queries additionally scoped by `orgId` from `auth()` — never from the request body; service-role usage quarantined and greppable.
- **Right-sizing policy engines:** hand-rolled `lib/authz.ts` + RLS for single-app org tenancy → CASL when UI and server share rules → Cerbos when Next.js and FastAPI share one policy source → OpenFGA only for genuine per-object sharing graphs. Never let an AI session introduce a PDP for a two-role app.

**Exemplars:** [stalniy/casl](https://github.com/stalniy/casl) (`defineAbilityFor` single-source abilities; @casl/prisma → WHERE clauses), [next-safe-action](https://github.com/next-safe-action/next-safe-action), [vercel/next-forge](https://github.com/vercel/next-forge) (centralized `packages/auth` + `packages/security`), [Supabase Clerk third-party-auth guide](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/auth/third-party/clerk.mdx) (copy its policy SQL verbatim), [cerbos/cerbos](https://github.com/cerbos/cerbos), [openfga/openfga](https://github.com/openfga/openfga).

**Baselines omit:** any auth below middleware; ownership scoping; server-action auth; the two-account negative test; the distinction between hiding UI and authorization.

### 3.4 Database RLS (Supabase)

Verified idioms (official docs + splinter lints):

- **Per-operation semantics:** SELECT/DELETE = USING only; INSERT = WITH CHECK only; **UPDATE = both** — USING without WITH CHECK lets a user rewrite `user_id`/`tenant_id` on visible rows (ownership-transfer escalation). Write **four separate policies**, never `FOR ALL`. `UPDATE ... RETURNING` needs a matching SELECT policy.
- **Performance idiom:** always `(select auth.uid())` / `(select auth.jwt())` — initPlan caches once per statement instead of per row (5ms vs multi-second at 100K rows; lint `auth_rls_initplan`). B-tree index every policy-filter column; keep explicit `.eq()` filters in app queries too.
- **Always `TO authenticated`** (or explicit role) — omitting TO runs the policy for anon. `auth.uid()` returns NULL for anon, so `null = user_id` filters *silently*: deny tests assert **empty results, not errors**.
- **Authorization data comes from `app_metadata` / a custom-claims hook — never `user_metadata`**, which any user updates themselves via `supabase.auth.updateUser()` (lint 0015: self-service privilege escalation).
- **With Clerk (native third-party integration; JWT template deprecated 2025-04-01):** `auth.uid()` does NOT work — identity = `auth.jwt()->>'sub'`, active org = `auth.jwt()->'o'->>'id'`. Blessed idiom: one STABLE helper like `requesting_owner_id()` returning `coalesce(org, sub)`, used in both USING and WITH CHECK.
- **SECURITY DEFINER functions:** pin `SET search_path = ''`, schema-qualify everything (lint 0011), live in a private schema, `REVOKE EXECUTE FROM anon, authenticated` when policy-internal. Use them for membership lookups to avoid recursive-policy errors.
- **Views bypass RLS by default** — create with `WITH (security_invoker = true)` on PG15+ (lint 0010).
- **Keys:** service_role/`sb_secret_*` carries BYPASSRLS. New `sb_publishable_*`/`sb_secret_*` format replaces legacy anon/service_role JWTs (deprecated end of 2026). Debug in layers: error 42501 = missing GRANT; empty result = USING; rejected write = WITH CHECK. Never "fix" RLS by switching to the service-role client.
- **Testing is first-class:** `supabase test db` runs pgTAP from `supabase/tests/`; supabase-test-helpers gives `tests.create_supabase_user()`, `tests.authenticate_as()`, `tests.clear_authentication()`, `tests.rls_enabled('public')` — the last is a single CI tripwire for the entire schema. Cautionary: vercel/nextjs-subscription-payments was archived Jan 2025 and its successor uses Drizzle without RLS — don't copy it for RLS patterns.

**Exemplars:** [usebasejump/basejump](https://github.com/usebasejump/basejump) (copy the team-accounts migrations + full pgTAP suite shape; unmaintained — patterns, not code), [usebasejump/supabase-test-helpers](https://github.com/usebasejump/supabase-test-helpers), [supabase/splinter](https://github.com/supabase/splinter) (run the Advisor lints in CI), [makerkit/nextjs-saas-starter-kit-lite](https://github.com/makerkit/nextjs-saas-starter-kit-lite), [supabase/dbdev](https://github.com/supabase/dbdev).

**Baselines omit:** RLS at all; WITH CHECK on UPDATE; DELETE policies (deletes silently affect 0 rows → a later session "fixes" it with service-role); initPlan wrapping; any RLS test.

### 3.5 Rate Limiting & Abuse

- **@upstash/ratelimit** is the canonical serverless limiter: `new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, '10 s'), analytics: true, prefix: 'rl:route' })`, keyed `userId ?? ip`. **It is fail-open by default** (5s timeout → allow): fail-closed requires your own wrapper on auth/email/LLM/payment routes. Leave ephemeral cache on (local denial of already-blocked keys during attacks).
- **Vercel WAF** rate limiting is coarse: fixed window on all plans, counters are **per-region** (distributed attackers exceed configured limits) — Upstash holds the strict global cap. `@vercel/firewall` `checkRateLimit('rule-id', {rateLimitKey})` lets you key WAF rules on identity; passing `rateLimitKey` *replaces* the IP bucket — compose `${orgId}:${userId}` deliberately.
- **Vercel BotID** (`botid` package): `withBotId(nextConfig)` + `initBotId({protect:[...]})` in instrumentation-client + server-side `checkBotId()` in the handler/action. Basic free; Deep Analysis (Kasada) $1/1000 on Pro. Routes not registered in `initBotId` make `checkBotId()` fail; local dev always returns `isBot:false`.
- **Server Actions POST to the page's own URL** — path-matched middleware/WAF rules never fire. Rate limit *inside* the action body: `auth()` → `ratelimit.limit(userId)` → work.
- **Don't rebuild Clerk's protections:** its Frontend API is per-IP rate limited (sign-ups: 5/10s), account lockout at 100 failed attempts/1h, Bot sign-up protection toggle. Your limits cover only custom endpoints you wrote.
- **Turnstile:** server-side `siteverify` POST (form-encoded `secret`+`response`) is the only enforcement; tokens single-use, 300s expiry. Client: @marsidev/react-turnstile. On Vercel, BotID is the frictionless alternative.
- **Idempotency (Stripe pattern, brandur.org/idempotency-keys):** `Idempotency-Key` header → Postgres `UNIQUE` + `INSERT ... ON CONFLICT` atomically; same key+params replays stored response; different params → 422; in-flight duplicate → 409. Plain Supabase table with RLS — no Redis needed.
- **Resend:** 10 req/s team-wide default; email endpoints are double-expensive (money + sender reputation) → per-user cap + per-IP limit + bot check + idempotent sends.
- **Layering:** WAF (coarse, per-region) → BotID/Turnstile (high-value paths) → Upstash (identity-keyed) → DB idempotency. Ship in observe mode (`analytics: true`, WAF Log action) for one traffic cycle, then enforce. Return 429 with `Retry-After` from `result.reset`.

**Exemplars:** [upstash/ratelimit-js](https://github.com/upstash/ratelimit-js) (copy `examples/nextjs*`), [vercel/vercel packages/firewall](https://github.com/vercel/vercel/tree/main/packages/firewall), [arcjet/arcjet-js](https://github.com/arcjet/arcjet-js) (two portable design rules: protect() in handlers not middleware; `decision.isErrored()` forces an explicit fail-mode branch), [marsidev/react-turnstile](https://github.com/marsidev/react-turnstile), [unkeyed/unkey](https://github.com/unkeyed/unkey) (5.4k★ — reference when API-key-scoped limits arrive).

**Baselines omit:** any limiter on Server Actions; the fail-mode decision; identity keying (IP-only blocks CGNAT users and not attackers); LLM token/cost budgets; idempotency; `Retry-After`.

### 3.6 Logging & Errors

- **Pino on Vercel:** requires `serverExternalPackages: ['pino', 'pino-pretty']` in next.config. **No transports in production** (worker-thread flushes are lost on function freeze) — plain JSON to stdout; Vercel parses it into filterable fields and Log Drains receive it structured. pino-pretty is dev-only.
- **Redaction is the PII control:** `redact: { paths: ['req.headers.authorization', 'req.headers.cookie', '*.password', '*.token', '*.apiKey', '*.secret', '*.email', ...] }` — explicit paths (~2% overhead) over wildcards (~50%); never derived from user input.
- **Dev/prod error asymmetry is the #1 trap:** in dev, full error messages reach the client from RSC/Server Actions; in prod Next.js masks them with a generic message + `digest` hash. Route handlers get **no** automatic masking. The `digest` is the free correlation ID — display it in error boundaries as the support code, never `error.message`.
- **next-safe-action `handleServerError`** = the allowlist pattern: log full error server-side with requestId; return real message only for `instanceof ActionError`; else `DEFAULT_SERVER_ERROR_MESSAGE`.
- **`instrumentation.ts` → `export const onRequestError = Sentry.captureRequestError`** is the only hook that sees Server Action, RSC, and middleware errors. Sentry: keep `sendDefaultPii` false; scrub via `beforeSend` (user, cookie/authorization headers, query strings) and `beforeBreadcrumb`.
- **Correlation for free:** `x-vercel-id` header, per-invocation requestId in Runtime Logs, `vercel logs --request-id`. Echo into `logger.child({ requestId, userId })`. **Fluid Compute:** one instance serves many concurrent requests — module-scope mutable log context bleeds between users; per-request child loggers or AsyncLocalStorage are mandatory; `waitUntil()` for telemetry flushes.
- **Audit trail:** supa_audit (archived Feb 2025 — vendor its trigger SQL, don't depend on it) or pgaudit (Supabase blocks `log_parameter` deliberately; keep `log_rows` off). With Clerk, the actor is `auth.jwt()->>'sub'`, never `auth.uid()`.
- **OWASP Logging Cheat Sheet:** log authn success/failure, authz failures, validation failures, privileged actions, sensitive-data access — with when/where/who/what. Never log: session IDs, tokens, passwords, connection strings, card/health data, `process.env`. Log user input as structured *fields*, never interpolated into message strings (JSON escaping is the CRLF-injection control). Logging failures never crash the request.

**Exemplars:** [pinojs/pino](https://github.com/pinojs/pino) (docs/redaction.md), [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) (Logging + Vocabulary), [next-safe-action](https://github.com/next-safe-action/next-safe-action), [supabase/supa_audit](https://github.com/supabase/supa_audit), [vercel/next-forge](https://github.com/vercel/next-forge) (observability as a workspace package), [getsentry/sentry-javascript](https://github.com/getsentry/sentry-javascript).

**Baselines omit:** redaction entirely; `console.log(evt.data)` in webhook handlers (a GDPR incident per `user.created`); `err.message` returned to clients (Postgres errors are chatty: tables, columns, constraints); `global-error.tsx`; any audit trail for service-role writes; any structured security event.

### 3.7 Boilerplate Survey (what "production-ready" actually ships)

Six starters surveyed: vercel/next-forge, nextjs/saas-starter, create-t3-app, official Supabase starter, fastapi/full-stack-fastapi-template, ixartz/SaaS-Boilerplate.

- **Cross-cutting result: across all six — ZERO ship a CSP, ZERO enforce rate limiting on any route, ZERO include a single authorization test, ZERO ship audit logging, ZERO validate file uploads.** "Production-ready" means auth + payments + observability, never abuse resistance.
- **next-forge fails open twice** (verified): `packages/security` silently no-ops without `ARCJET_KEY`; the Stripe webhook returns **HTTP 200** "Not configured" without `STRIPE_WEBHOOK_SECRET` — Stripe marks delivery successful and never retries. It also sets `contentSecurityPolicy: false`. Copy its *composition* (Nosecone headers in middleware, `createRateLimiter()` wrapper, raw-body Stripe verification), fix its defaults.
- **nextjs/saas-starter's** middleware matcher **explicitly excludes `/api`**; zero headers; no test script. But its `validatedActionWithUser(schema, action)` wrapper (Zod + auth + team scoping per action) is the pattern to mandate.
- **create-t3-app's** two structural wins: t3-env build-failure env validation and tRPC `protectedProcedure` (type-narrowed non-null session → "forgot the auth check" is a compile error). Nothing else ships.
- **Official Supabase starter** ships *only* session-refresh middleware — zero RLS policies, no migrations, no service-role handling. The entire authorization model is homework. Its inline warning is load-bearing: on Fluid Compute, create Supabase clients **per-request**, never module-global.
- **full-stack-fastapi-template** has the only fail-closed config in the survey: pydantic-settings `model_validator` that **raises at boot** if any secret equals `'changethis'` outside development. Also pwdlib Argon2+bcrypt with rehash-on-verify, dependency-chain RBAC. Omits: rate limiting, headers, lockout, audit; CORS pins origin but wildcards methods/headers with credentials.
- **zhanymkanov/fastapi-best-practices** (17.9k★, doc repo): chained-dependency authorization (`parse_jwt_data → valid_owned_post`) — FastAPI's `protectedProcedure` equivalent.
- **ixartz/SaaS-Boilerplate**: closest stack match (Clerk+Zod+t3-env), reference Clerk org-gating middleware, only starter with a real test harness (Vitest+Playwright+Checkly) — but zero security tests.

**Exemplars:** [vercel/next-forge](https://github.com/vercel/next-forge), [fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template), [t3-oss/create-t3-app](https://github.com/t3-oss/create-t3-app), [nextjs/saas-starter](https://github.com/nextjs/saas-starter), [vercel/next.js examples/with-supabase](https://github.com/vercel/next.js/tree/canary/examples/with-supabase), [zhanymkanov/fastapi-best-practices](https://github.com/zhanymkanov/fastapi-best-practices), [ixartz/SaaS-Boilerplate](https://github.com/ixartz/SaaS-Boilerplate).

### 3.8 Secrets & Supply Chain

- **`NEXT_PUBLIC_` = inlined into the client bundle at build time, public forever.** Allowed: Supabase URL + publishable key, Clerk publishable key, site URL, analytics IDs. Everything else — `SUPABASE_SERVICE_ROLE_KEY`, `CLERK_SECRET_KEY`, `RESEND_API_KEY`, `UPSTASH_REDIS_REST_TOKEN`, webhook secrets — never. Ground truth after build: `grep -r 'sb_secret\|service_role' .next/static/` must be empty.
- **Three-layer secret scanning:** gitleaks pre-commit hook + `gitleaks-action@v3` in CI (fetch-depth: 0; free `GITLEAKS_LICENSE` for org repos) + GitHub push protection (server-side, un-skippable). TruffleHog complements with **live verification** of 700+ credential types (`--results=verified,unknown`, exits 183 on active creds) — the right blocking signal for AI-generated noise. A committed secret requires **rotation**, never just deletion.
- **The 2025 npm attack wave is the motivation:** Sept 2025 'qix' phishing (chalk/debug, ~2.6B weekly downloads, wallet-drainer) and the **Shai-Hulud worm** (500+ packages, postinstall payloads stealing npm/GitHub/cloud creds and self-propagating). Both delivered via lifecycle scripts and fresh versions — exactly what these settings neutralize: pnpm `minimumReleaseAge: 4320`, `blockExoticSubdeps: true`, `trustPolicy: no-downgrade`, `allowBuilds: []` allowlist; npm `.npmrc` `ignore-scripts=true` + `save-exact=true`; `npm ci`/`--frozen-lockfile` in CI.
- **GitHub Actions SHA-pinning:** March 2025 tj-actions/changed-files repointed every tag at a malicious commit, leaking secrets from 23,000+ repos; SHA-pinned users unaffected. `uses: actions/checkout@<40-char-sha> # v5.0.0`; pinact rewrites and `pinact run --check` gates CI; Dependabot bumps SHA+comment together. Top-level `permissions: contents: read` in every workflow.
- **SAST:** CodeQL default setup free on public repos; private repos use Semgrep CE (`p/typescript`, `p/nextjs`, `p/react` + repo-local `.semgrep/` rules). Dependabot covering npm + **github-actions** + pip.
- **Vercel hygiene:** mark secrets Sensitive; sync local via `vercel env pull .env.local`; `.gitignore` has `.env*` with `!.env.example`; `.env.example` lists every key with server-only annotations.

**Exemplars:** [t3-oss/t3-env](https://github.com/t3-oss/t3-env), [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (28.8k★; feature-complete, successor is Betterleaks), [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog), [suzuki-shunsuke/pinact](https://github.com/suzuki-shunsuke/pinact), [bodadotsh/npm-security-best-practices](https://github.com/bodadotsh/npm-security-best-practices) (2025 attack wave → copy-pasteable config), [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules), [ossf/package-manager-best-practices](https://github.com/ossf/package-manager-best-practices).

**Baselines omit:** all of it — inline `process.env.X!` everywhere, tag-pinned actions, unrestricted lifecycle scripts, no scanner, no `.env.example`, no SAST.

### 3.9 Headers, Platform & Security Testing

- **CSP per the official Next.js guide:** middleware-generated nonce, `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`, plus `default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`; `'unsafe-eval'` only when `NODE_ENV === 'development'`. Caveat: nonces force full dynamic rendering (ISR/PPR incompatible) — use a strict allowlist CSP or experimental SRI instead; never delete the CSP to keep ISR.
- **Vercel HSTS asymmetry:** `*.vercel.app` gets `max-age=63072000; includeSubDomains; preload` automatically; **custom domains get only `max-age`** — set the full header yourself.
- **CSRF split:** Server Actions have built-in Origin-vs-Host checking (configure `serverActions.allowedOrigins` behind proxies). **Route Handlers have zero CSRF protection** — cookie-authenticated mutating handlers need an explicit Origin allowlist check; never mutate on GET. Webhooks are exempt from Origin checks but must verify signatures.
- **CORS anti-pattern to ban:** reflecting the request Origin (`allowedOrigin || '*'`). Correct: exact-match allowlist; never `*` with credentials.
- **@nosecone/next** (in arcjet-js monorepo; standalone repo 404s): one-call hardened defaults including the COOP/CORP/COEP trio and `X-XSS-Protection: 0`.
- **Test assembly (no canonical repo exists — build from parts):** Playwright `request.get()` header-assertion spec; per-role `storageState` authz matrix (anon/member/other-org/admin × route manifest → expected status per cell, with a completeness check on the manifest); pgTAP RLS suite via `supabase test db`; Semgrep repo-local rules as permanent regression gates (every incident becomes a rule); Zod fixture round-trips (valid / +`role:'admin'` / type-confused → b and c must fail).
- **Preview deployments:** keep Standard Protection; CI uses Protection Bypass for Automation (`x-vercel-protection-bypass` header); OPTIONS Allowlist for CORS preflights — never disable protection.
- **Version floors in CI:** `next >= 15.2.3` (or `>= 14.2.25`), `@clerk/nextjs >= 6.39.2` (or `>= 7.2.1`) — a lockfile-reading script suffices.

**Exemplars:** [usebasejump/supabase-test-helpers](https://github.com/usebasejump/supabase-test-helpers), [usebasejump/basejump](https://github.com/usebasejump/basejump), [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules), [arcjet/arcjet-js](https://github.com/arcjet/arcjet-js), [next.js examples/with-strict-csp](https://github.com/vercel/next.js/tree/canary/examples/with-strict-csp) (diff against this instead of generating CSP from memory).

### 3.10 File Uploads & Supabase Storage

- **Storage has its own RLS surface** (`storage.objects`, scoped `bucket_id = '...'`). A bucket created `public: true` makes every object world-readable with **no policy check on reads** — the storage equivalent of a table without RLS.
- **Per-user isolation:** first path segment = user ID: `(storage.foldername(name))[1] = (select auth.jwt()->>'sub')` (Clerk; `auth.uid()` cannot represent Clerk IDs). Use `owner_id` (text), never the deprecated `owner` column. Upsert needs INSERT+SELECT+UPDATE policies.
- **Bucket guardrails AI never sets:** `createBucket('user-docs', { public: false, fileSizeLimit: '10MB', allowedMimeTypes: [...] })` — note allowedMimeTypes checks the *declared* type only (extension-inferred from the client's filename → attacker-controlled).
- **Vercel caps make proxy uploads a trap:** 4.5 MB hard function body limit; Server Actions default 1 MB. Anything larger goes direct-to-storage via `createSignedUploadUrl(path)` (2h token) minted by a Clerk-authenticated, rate-limited endpoint that **builds the path server-side** (`${userId}/${crypto.randomUUID()}.${ext}`) and never signs a client-supplied path.
- **SVG stored-XSS is real:** exclude `image/svg+xml` from public buckets; sanitize-by-transcoding with sharp (`sharp(buf, {limitInputPixels: 268402689}).rotate().webp().toBuffer()` — destroys scripts/polyglots, strips EXIF GPS, caps decompression bombs); force `?download` on anything not re-encoded. The supabase.co origin split protects the app origin **only if you never proxy raw uploaded bytes** through app routes.
- **Magic bytes:** npm `file-type` (v22, ESM-only — cannot detect SVG/text: treat undetectable as reject); Python `python-magic` (`magic.from_buffer(head, mime=True)`, needs system libmagic). FastAPI `UploadFile` has **no size limit by default** — stream in 64 KB chunks with a byte counter → 413; never bare `await file.read()`; never trust `file.filename`/`file.content_type`.
- **Service-role uploads bypass all storage RLS** — such routes must enforce ownership (caller userId == first path segment) and content validation themselves.
- No Semgrep registry rules exist for Supabase Storage — write custom ones (getPublicUrl on non-approved buckets; upload path tainted by `file.name`; `upsert: true`; unauthenticated `createSignedUploadUrl`).

**Exemplars:** [supabase/storage](https://github.com/supabase/storage), [supabase user-management example](https://github.com/supabase/supabase/tree/master/examples/user-management/nextjs-user-management) (tighten its demo-ware "anyone can upload" policy), [sindresorhus/file-type](https://github.com/sindresorhus/file-type), [lovell/sharp](https://github.com/lovell/sharp), [ahupp/python-magic](https://github.com/ahupp/python-magic), OWASP File Upload Cheat Sheet.

### 3.11 Payments & Billing

- **Price integrity:** Checkout Sessions created server-side only, `line_items` from a server-side allowlist of Price IDs (Zod enum / DB lookup). Reject any body containing `amount`, `unit_amount`, `price_data`, `currency`, or raw `price_...` — AI code routinely turns a client integer into the charge amount.
- **Fulfillment:** one idempotent `fulfillCheckout(sessionId)` triggered by `checkout.session.completed` AND `checkout.session.async_payment_succeeded` webhooks (success page is a latency optimization calling the same function). Inside: re-retrieve the session from Stripe with `expand:['line_items']`; proceed only if `payment_status !== 'unpaid'` (ACH sessions complete unpaid); resolve WHO from `client_reference_id`/`metadata.userId` — never the visitor's cookie. Never grant from `?success=true` (EnrichLead's console-bypassed paywall).
- **Webhook hardening:** verify the **raw body** (`await req.text()`); keep the SDK's default 5-minute tolerance (never `tolerance: 0`); Stripe is at-least-once and **unordered** — fetch current state from the API, don't trust payload snapshots; dedupe with a DB `processed_events(event_id PRIMARY KEY)` insert, never an in-memory Set; missing `STRIPE_WEBHOOK_SECRET` = boot failure or 5xx, **never 200** (the next-forge bug — Stripe stops retrying and billing events vanish silently).
- **The t3dotgg pattern:** one `syncStripeDataToKV(customerId)` that fetches CURRENT state from the Stripe API and overwrites the store, called from all ~17 relevant events + eager success-page sync. Pre-create the customer, store userId→customerId, enable "limit customers to one subscription."
- **Revocation or you're giving it away:** handle `customer.subscription.updated/deleted` and `invoice.payment_failed`; entitlement checks query `status IN ('active','trialing') AND current_period_end > now()` in the data layer. Supabase billing tables written **only** by the webhook handler (service-role); RLS grants owner SELECT and no write policies.
- **Clerk Billing:** not Stripe Billing — the only trustworthy check is server-side `const { has } = await auth(); has({ plan: 'pro' })` / `has({ feature: 'x' })` (`org:` prefix for B2B). `<PricingTable>`/`<Protect>` are rendering hints. Its webhook lifecycle events verify via `verifyWebhook` (testable with `npx clerk webhooks verify`). No published bypass writeups yet — risk inferred from architecture.
- **Credits:** single atomic `UPDATE credits SET balance = balance - $x WHERE user_id = $u AND balance >= $x RETURNING balance` in a SECURITY DEFINER RPC + `CHECK (balance >= 0)`. Never SELECT-then-UPDATE, never client-side arithmetic.
- **Billing red-team checklist (release blockers):** forge success redirect; replay a webhook twice; tamper price/amount; unsigned webhook; paid endpoint as free/cancelled user via curl; parallel credit double-spend; boot without webhook secret.

**Exemplars:** [t3dotgg/stripe-recommendations](https://github.com/t3dotgg/stripe-recommendations) (6.4k★), [nextjs/saas-starter](https://github.com/nextjs/saas-starter), [vercel/nextjs-subscription-payments](https://github.com/vercel/nextjs-subscription-payments) (archived; copy the admin-writes-only RLS schema), [stripe-samples/subscription-use-cases](https://github.com/stripe-samples/subscription-use-cases), [clerk/skills — clerk-billing](https://github.com/clerk/skills/blob/main/skills/features/clerk-billing/SKILL.md) (installed locally; load before writing Clerk Billing code), next-forge as the cautionary fail-open exhibit.

### 3.12 SSRF & Outbound Fetches

- **Sinks in this stack:** link/OG previews, "import from URL", avatar-from-URL, RAG ingestion; **LLM tool-call URLs (attacker-controlled via prompt injection, LLM06)**; user-configured outbound webhooks; URL-following document processors. SSRF is now folded into A01:2025.
- **Vercel does NOT block metadata/private ranges for normal Functions** — egress filtering exists only in Vercel Sandbox; Secure Compute (Enterprise) gives a VPC. Validate in app code regardless. FastAPI containers (Docker/Fly/Railway) have live IMDS (169.254.169.254, fd00:ec2::254, metadata.google.internal, 100.100.100.200), loopback admin ports, RFC 1918/4193 ranges.
- **Bypasses that defeat naive blocklists (all confirmed):** userinfo (`http://ok.com@169.254.169.254/`), decimal/octal/hex IPs (`2130706433`, `0177.0.0.1`, `0x7f000001`, `127.1`), IPv6-mapped forms (`[::ffff:a9fe:a9fe]` — bypassed even Pydantic AI's first fix: CVE-2026-46678/48782), DNS rebinding (TOCTOU), redirect-based bypass. CVE-2025-9960 (is-localhost-ip) proves random "is-private" packages can't be trusted.
- **Correct control = resolve-then-connect IP pinning:** resolve, verify every A/AAAA record is public unicast (binary check, not string match), connect to that pinned IP. **Node gotcha:** built-in global fetch (undici) silently ignores `{agent}` — use got/axios/node-fetch + `request-filtering-agent`, or a hardened undici dispatcher. Python: stdlib `ipaddress` + `socket.getaddrinfo` (Advocate/SafeURL are abandoned — don't recommend).
- **Also required:** redirects disabled (`maxRedirects: 0` / `follow_redirects=False`) or each hop re-validated; scheme allowlist {http, https} (deny file://, gopher://, dict://); hard timeouts ≤5s + streamed body-size caps (anti port-scanning/exfil); Case-1 hostname allowlists whenever destinations are known.
- **Stack CVEs:** CVE-2025-57822 (Next.js middleware `NextResponse.next()` reflecting user headers → SSRF; fixed 14.2.32/15.4.7), CVE-2026-8768 (Vercel AI SDK ≤3.0.97 download-URL validation), CVE-2026-25580 (Pydantic AI, fixed 1.56.0 — its fix is the recipe to copy).
- **Architecture:** run untrusted/agent fetches in a context holding no secrets — dedicated fetcher or egress proxy (smokescreen/pipelock) — so a bypass still can't read metadata or exfiltrate credentials. Semgrep `p/ssrf` (taint mode) flags tainted URLs reaching HTTP clients without the named validator.

**Exemplars:** [azu/request-filtering-agent](https://github.com/azu/request-filtering-agent) (3.2.1, anti-rebinding at connect time), [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [stripe/smokescreen](https://github.com/stripe/smokescreen), [Pydantic AI advisory GHSA-2jrp-274c-jhv3](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-2jrp-274c-jhv3), [luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock), [CVE-2025-57822 changelog](https://vercel.com/changelog/cve-2025-57822).

---

## 4. The Gap Matrix — What Even the Best Boilerplates Don't Give You

Verified across next-forge, nextjs/saas-starter, create-t3-app, the official Supabase starter, full-stack-fastapi-template, and ixartz/SaaS-Boilerplate:

| Control | Best available in any starter | What's still missing everywhere |
|---|---|---|
| CSP / security headers | next-forge ships headers via Nosecone — **with CSP explicitly disabled** | A real production CSP; HSTS includeSubDomains/preload on custom domains |
| Rate limiting | next-forge ships an Upstash wrapper **wired to zero routes** | Any enforced limit; fail-mode decisions; LLM token/cost budgets |
| RLS | Official Supabase starter ships **zero policies, zero migrations** | Policies at all; WITH CHECK on UPDATE; DELETE policies; RLS tests; storage.objects policies |
| Auth depth | All starters: middleware-only (two even exclude `/api` or dot-files from the matcher) | Auth in handlers/actions/DAL; the CVE-2025-29927 lesson |
| Fail-closed config | Only full-stack-fastapi-template (raises on `'changethis'` secrets) | Every JS starter fails open on missing security env |
| Webhook verification | Only next-forge (Stripe) — and it fails open without the secret | Clerk/svix verification; replay/idempotency; payload schema after signature |
| Security tests | ixartz has a test harness — **zero security tests in it** | IDOR/cross-tenant tests; unauthenticated-401 sweeps; header assertions; RLS pgTAP |
| Secrets discipline | create-t3-app/t3-env (build-time env validation) | Service-role isolation pattern; secret scanning; SHA-pinned actions; lifecycle-script restrictions |
| Audit & security logging | None | Structured authn/authz events; audit rows for privileged mutations; redaction |
| Abuse/bots/CAPTCHA, file-upload validation, idempotency, SSRF validation, LLM output handling | None anywhere | Everything |

**Conclusion:** every starter is a *feature* baseline. The playbook's §5 rules are precisely the delta between "production-ready starter" and "survives contact with the internet."

---

## 5. Consolidated Operational Rules (the future CLAUDE.md)

Deduplicated, grouped, phrased as testable imperatives. Each rule states its check.

### A. Authentication & Authorization

1. NEVER treat middleware as the authorization boundary. Every Route Handler, Server Action, and DAL function calls `const { userId, orgId } = await auth()` and rejects unauthenticated callers itself. *Test:* grep `app/api/**` and every `'use server'` file for an `auth()`/`authActionClient` reference — zero misses; curl with `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` and no session → still 401.
2. Pin version floors in CI: `next >= 15.2.3` (or `>= 14.2.25`; `>= 14.2.32`/`15.4.7` for CVE-2025-57822), `@clerk/nextjs >= 6.39.2` (or `>= 7.2.1`), Vercel AI SDK `> 3.0.97`. *Test:* lockfile-reading CI script.
3. All mutations go through a single `authActionClient` (next-safe-action) or equivalent wrapper (auth → org/permission → Zod input). Bare exported `'use server'` mutations are banned. *Test:* grep for `'use server'` files not importing the shared client.
4. Every query taking an object ID also filters by caller identity (`.eq('org_id', orgId)` / `AND user_id = $caller`) and returns 404 on zero rows. Fetch-then-check is forbidden. *Test:* seeded account B requests account A's resource IDs → 404 on every endpoint.
5. Derive `userId`/`orgId`/`role` ONLY from `await auth()` — never from request body, query params, or client props. *Test:* grep input schemas for `userId|orgId|role|isAdmin|plan|amount`; every hit needs written justification.
6. Centralize policy in one module (`lib/authz.ts` / CASL `defineAbilityFor`). Role-string literals outside it: zero. Server-side Clerk `has()` uses custom permissions only; handle the no-active-org case; declare a global `ClerkAuthorization` interface.
7. Never place auth checks in `layout.tsx`; never rely on `<Protect>`/`<Show>`/conditional rendering for security — UX only. *Test:* every protected page performs its own server-side check or calls a DAL that does.
8. Fail closed: authz helpers throw or return 404 on denial; catch-alls never convert denials into empty-success responses.

### B. Database & RLS

9. Every `CREATE TABLE` in an exposed schema is immediately followed in the **same migration** by `ENABLE ROW LEVEL SECURITY` plus policies. *Test:* `tests.rls_enabled('public')` passes in `supabase test db`; `select tablename from pg_tables where schemaname='public' and rowsecurity=false` → zero rows.
10. Four separate policies per table (never `FOR ALL`): SELECT/DELETE = USING; INSERT = WITH CHECK; UPDATE = **both**, same predicate. *Test:* pgTAP — UPDATE another user's row and reassign `owner_id` both fail.
11. Always wrap auth functions: `(select auth.uid())` / `(select auth.jwt())`; always `TO authenticated` (or explicit role); index every policy-filter column in the same migration; keep explicit `.eq()` filters in app queries. *Test:* splinter `auth_rls_initplan` zero findings; grep migrations for `create policy` lines lacking a TO clause.
12. With Clerk: identity = `auth.jwt()->>'sub'`, org = `auth.jwt()->'o'->>'id'`, centralized in one STABLE helper used in USING and WITH CHECK. Never `auth.uid()`, never tenant_id from the request body without a WITH CHECK re-deriving it. Never authorize from `user_metadata` — `app_metadata`/custom claims/membership tables only.
13. SECURITY DEFINER functions: `SET search_path = ''`, schema-qualified names, private schema, `REVOKE EXECUTE FROM anon, authenticated` unless intentionally an API; use them for membership lookups (anti-recursion). Views over RLS tables: `WITH (security_invoker = true)`. *Test:* splinter lints 0011 and 0010 zero rows.
14. Run splinter Security Advisor lints in CI; treat `rls_disabled_in_public`, `policy_exists_rls_disabled`, `security_definer_view`, `auth_users_exposed`, `function_search_path_mutable`, `rls_references_user_metadata` as build-breaking.
15. Ship pgTAP per table: owner CRUDs own rows; authenticated non-owner sees 0 rows and cannot write cross-tenant (assert **empty results**, not errors); anon sees only intentionally public rows. Run `supabase test db` on every migration PR.
16. Debug in layers — 42501 = grants, empty set = USING, rejected write = WITH CHECK. NEVER "fix" an RLS symptom by switching to the service-role client, adding `USING (true)`, or disabling RLS.
17. Balance/credit/quota/inventory mutations are single atomic statements (`UPDATE ... WHERE ... AND balance >= $x RETURNING`) or SERIALIZABLE transactions with retry; uniqueness enforced by DB UNIQUE + ON CONFLICT, never check-then-insert. *Test:* 10 parallel spends exceeding balance → successful total ≤ starting balance.
18. Create Supabase/DB clients **per-request** on Fluid Compute, never module-global.

### C. Input Validation

19. Every Server Action and Route Handler parses input through a Zod schema before any other logic; `const input = Schema.parse(raw)` is the first meaningful statement, and `raw` is never referenced again (no spreading originals into DB calls). *Test:* handlers reading arguments before a `.parse(`/`.inputSchema(` fail review.
20. `z.strictObject()` for ALL inbound untrusted payloads; `passthrough`/`looseObject` banned on untrusted input. *Test:* `grep -rn 'passthrough\|looseObject' src/` → zero hits in inbound schemas.
21. `z.coerce.boolean()` is banned — use `z.stringbool()`; `z.coerce.number()` only behind a non-empty-string guard or zod-form-data. Validate route params/foreign keys as `z.uuid()` (or exact format), enums as `z.enum()`, pagination as bounded ints. *Test:* grep `coerce.boolean` → zero.
22. Polymorphic payloads = discriminated unions (TS and Pydantic), never one schema of co-dependent optionals.
23. Validation failures return 400/422 with field-level issues only (`z.flattenError`) — never echo submitted values, stacks, or schema internals; never fall through to defaults.
24. Pydantic v2: body models set `ConfigDict(extra='forbid')` (internal DTOs also `strict=True`); query/path models stay lax; every route declares `response_model=`.
25. One schema module (`lib/schemas/`) shared by server and client; derive variants with `.pick()/.omit()/.extend()`. Zod v4 hygiene: top-level `z.email()`/`z.uuid()`/`z.url()`; know `.default()` short-circuits (use `.prefault()`); run `npx zod-v3-to-v4`, don't hand-port v3 snippets from training data.

### D. Secrets & Environment

26. Exactly one `src/env.ts` via `@t3-oss/env-nextjs` (`emptyStringAsUndefined: true`), imported in `next.config.ts`. All other files import `env` from it. *Test:* delete a required var → `next build` fails; `grep -rn 'process.env.' src/ app/` hits only env.ts; `SKIP_ENV_VALIDATION` unset in all Vercel environments. Python: pydantic-settings instantiated at module import, with a validator raising on placeholder secrets outside development.
27. No secret ever carries `NEXT_PUBLIC_`. Allowed public vars: Supabase URL + publishable key, Clerk publishable key, site URL, analytics IDs. *Test:* after build, `grep -r 'sb_secret\|service_role' .next/static/` empty; no `NEXT_PUBLIC_*` name matching `/secret|service|private|api_key/i`.
28. `SUPABASE_SERVICE_ROLE_KEY` is read in exactly one module that begins with `import 'server-only'`, imported only by webhooks/cron/admin jobs, never middleware/edge, and every callsite manually scopes by org/user with an audit row. *Test:* `grep -rln 'SERVICE_ROLE' src/ | grep -v server` empty. Prefer `sb_publishable_*`/`sb_secret_*` keys (legacy JWTs deprecated end 2026); rotate immediately on any client-artifact/chat/URL exposure.
29. `.gitignore` contains `.env*` (except `.env.example`) before the first commit; `.env.example` lists every key with server-only annotations. *Test:* `git ls-files | grep -E '\.env'` returns only `.env.example`.
30. gitleaks as pre-commit hook AND CI job (`gitleaks-action@<SHA>`, fetch-depth 0) plus TruffleHog (`--results=verified,unknown`); GitHub push protection on. A committed secret = rotate at the provider, always. *Test:* seeded fake AWS key on a test branch fails CI.
31. Vercel secrets marked Sensitive; local sync only via `vercel env pull .env.local`; secrets referenced by variable name only in chat/code/logs.

### E. Rate Limiting & Abuse

32. Every public mutating endpoint (route handler AND Server Action) invokes a limiter before expensive work: `@upstash/ratelimit` with `Redis.fromEnv()`, `Ratelimit.slidingWindow(N, window)`, per-route `prefix`, `analytics: true`. Never an in-process Map on Vercel. *Test:* grep POST handlers and `'use server'` functions for a limit call preceding DB/LLM/email work; Nth+1 request in window → 429 with `Retry-After` from `reset`.
33. Key authenticated traffic on Clerk `userId`, anonymous on platform IP (`x-real-ip` / first `x-forwarded-for` entry / `ipAddress()` from @vercel/functions — never a client-inventable header); expensive endpoints run BOTH limiters.
34. Choose fail mode explicitly per endpoint in code: auth/payment/email/LLM routes fail CLOSED (try/catch → 503/429 on Redis error); cheap idempotent reads may fail open. Upstash's own default (5s timeout → allow) is fail-open — your wrapper provides fail-closed.
35. Rate limit Server Actions inside the action body (`auth()` → `ratelimit.limit(userId ?? ip)` → work); middleware/WAF path rules never fire for actions.
36. LLM routes: `checkBotId()` first (path registered in `initBotId`, `withBotId` in next.config) → per-user sliding limit → daily token/cost budget checked BEFORE creating the model stream.
37. Email routes (Resend): Turnstile/BotID for anonymous senders; per-user daily cap + per-IP limit; idempotency key per send; stay under the 10 req/s team cap. Turnstile verified server-side only (form-encoded `secret`+`response` to siteverify; single-use, 300s).
38. Don't rebuild Clerk-hosted auth protection: enable Bot sign-up protection and Account Lockout in the dashboard; your limits cover only custom endpoints.
39. Payment/order/email POSTs accept an `Idempotency-Key`: `UNIQUE` column claimed via `INSERT ... ON CONFLICT DO NOTHING` in the side-effect transaction; same key replays stored response; different params → 422; concurrent duplicate → 409; RLS-scoped; TTL cleanup.
40. Layer: Vercel WAF (remember: per-region counters) → BotID/Turnstile → Upstash identity-keyed → DB idempotency. Ship in observe mode one traffic cycle, then enforce.

### F. Webhooks & Payments

41. Every webhook verifies the provider signature over the **raw body** before any parsing: Clerk `verifyWebhook(req)` (`CLERK_WEBHOOK_SIGNING_SECRET`), Stripe `constructEvent(await req.text(), sig, secret)` with default 5-min tolerance (never `tolerance: 0`), other Svix providers via svix. 400/401 on failure, no side effects, no payload echoed back. *Test:* forged unsigned POST → 400/401.
42. Missing signing secret = build/boot failure or 5xx from the route — NEVER 200 (silent event loss). All security-relevant env fails closed at module load.
43. After the signature, parse the event with a discriminated union on `event.type`; allowlist handled types (mirror in the provider dashboard); 200 without side effects for the rest; keep handlers fast.
44. Dedupe with the database: `processed_events(event_id PRIMARY KEY)` inserted before side effects; UNIQUE on `checkout_session_id` in fulfillments. *Test:* `stripe trigger` the same event twice → exactly one fulfillment.
45. Checkout Sessions: server-side only; Price-ID allowlist; reject bodies containing `amount|unit_amount|price_data|currency|price_...`; set `client_reference_id`/`metadata.userId` to the authenticated user; reuse the stored Stripe customer. *Test:* tampered priceId/amount POST → 400.
46. Fulfillment only via idempotent `fulfillCheckout(sessionId)` from the completed/async-succeeded webhooks; re-retrieve from Stripe; `payment_status !== 'unpaid'`; identity from the session, never the visitor. *Test:* `/success?session_id=cs_test_fake` while logged in → no entitlement.
47. Subscription state: sync-don't-mutate — fetch current state from the Stripe API on every relevant event and overwrite (`syncStripeDataToKV`). Handle revocation (`subscription.updated/deleted`, `invoice.payment_failed`; Clerk Billing: `subscriptionItem.canceled/ended/pastDue`, `paymentAttempt.updated`). Billing tables written only by the webhook handler; RLS = owner SELECT, no write policies. Entitlement checks in the data layer (`status IN ('active','trialing') AND current_period_end > now()`, or Clerk `has({plan})`). *Test:* curl a paid endpoint as a free/cancelled user → 403; cancel in dashboard → access revoked after webhook.
48. Block trial/coupon farming: existing customer id reuse, prior-subscription check, Stripe "limit customers to one subscription." Run the 7-item billing red-team checklist (§3.11) before every deploy.

### G. Logging & Errors

49. Pino JSON to stdout in production, no transports; pino-pretty gated on development; `serverExternalPackages: ['pino','pino-pretty']` in next.config. Every `pino()` sets `redact` (authorization/cookie headers, `*.password|token|apiKey|secret|email` at minimum, explicit paths preferred, never user-derived).
50. Never return `err.message`/`err.stack` to the client. Server Actions: next-safe-action `handleServerError` (log full + requestId; real message only for `ActionError`; else generic). Route handlers: top-level try/catch → log `{err, requestId}` → `{ error: 'Internal error', requestId }` 500. *Test:* force a DB error → HTTP body contains no stack frames or SQL text.
51. `app/` contains `error.tsx` (displays `error.digest` as support code, `reset()`) and `global-error.tsx` (own `<html>/<body>`). `instrumentation.ts` exports `onRequestError` (Sentry: `Sentry.captureRequestError`). Sentry: `sendDefaultPii` false; `beforeSend` strips user/cookies/authorization/query strings; `beforeBreadcrumb` scrubs console breadcrumbs.
52. Log per OWASP vocabulary as structured JSON: `authn_login_success/fail`, `authz_fail`, `input_validation_fail`, `rate_limit_exceeded`, privileged actions — with timestamp, requestId, actor, outcome; repeated failures queryable for alerting. Never log tokens, cookies, `process.env`, raw webhook payloads (`evt.type` + `evt.data.id` only), or card/health data. User input as fields, never interpolated; cap field length (~512). Logging failures are swallowed, never crash the request.
53. Every sensitive mutation (role/billing change, deletion, any service-role write, export) writes an audit row {actor (`auth.jwt()->>'sub'`), action, target, redacted old/new, requestId, created_at} in the same transaction; audit table has RLS with no app write policies and no deletes.
54. Per-request child loggers (`logger.child({ requestId })` from `x-vercel-id` or `crypto.randomUUID()`) or AsyncLocalStorage — no module-scope mutable context on Fluid Compute; `waitUntil()` for telemetry flushes.

### H. Headers, CSRF, CORS, Cookies

55. Set the full header suite in `next.config` headers() or @nosecone/next: CSP (nonce-based per the official guide; `frame-ancestors 'none'`; unsafe-* gated on development; never `contentSecurityPolicy: false`), `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (Vercel doesn't set the full header on custom domains), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP `same-origin`. *Test:* Playwright/curl header-assertion spec in CI on one page + one API route.
56. Cookie-authenticated mutating Route Handlers verify Origin against an explicit allowlist (403 on mismatch) and never mutate on GET; Server Actions rely on built-in Origin/Host checking (`serverActions.allowedOrigins` behind proxies); webhooks are Origin-exempt but signature-verified.
57. CORS: explicit OPTIONS handler per cross-origin route; exact-match origin allowlist from env; never `*` with credentials; never reflect the request Origin without an `includes()` check. Python: `allow_origins=[FRONTEND_HOST]`, enumerated methods/headers.
58. Custom cookies: `httpOnly, secure, sameSite: 'lax'` minimum, `__Host-` prefix. (Non-Clerk password flows only: argon2id + bcrypt fallback with rehash-on-verify, jose-signed JWTs, ≤24h expiry.)
59. Preview deployments keep Standard Protection; CI uses Protection Bypass for Automation; OPTIONS Allowlist for preflights — never disable protection.

### I. File Uploads & Storage

60. Buckets private by default, created with `fileSizeLimit` + `allowedMimeTypes`; never `image/svg+xml`, `text/html`, or wildcard `image/*` on a public bucket. *Test (CI SQL/pgTAP):* public-bucket list equals the committed allowlist; no bucket lacks size/mime limits; every private bucket has storage.objects policies (committed as migrations, never dashboard-only).
61. Server generates the full object path (`${userId}/${crypto.randomUUID()}.${ext}` — ext from the server-side allowlist decision); user filenames go in a DB column for display only; `upsert: true` only with an owner-pinned UPDATE policy. Clerk policies compare `(storage.foldername(name))[1]` / `owner_id` to `(select auth.jwt()->>'sub')`.
62. Files > ~1 MB go direct-to-storage: Clerk-authenticated, rate-limited, Zod-validated endpoint mints `createSignedUploadUrl` for a server-built path — never a client-supplied one. (Vercel hard cap: 4.5 MB.)
63. Validate content, not declarations: `fileTypeFromBuffer` mime must equal the allowlisted expectation (undetectable = reject); images sanitized by sharp transcode (`limitInputPixels`, `.rotate().webp()`) with explicit `contentType`; FastAPI streams with a byte-counter → 413, checks `magic.from_buffer` on the head, never trusts `filename`/`content_type`.
64. Serving: private files only via short-expiry `createSignedUrl` after a path-prefix ownership check; non-re-encoded types linked with `?download=`; never proxy raw uploaded bytes through app-origin routes. Service-role storage paths do their own ownership + content checks (RLS is bypassed).

### J. SSRF & Outbound Fetches

65. Every server-side fetch whose URL derives from request input, LLM tool-call arguments, or stored user-configured destinations goes through one named validator (`assertPublicUrl`/`safeFetch`) — no direct fetch/axios/httpx on such URLs. *Test:* Semgrep `p/ssrf` taint rule + custom rule requiring the validator.
66. The validator: scheme ∈ {http, https}; reject userinfo (`@`); resolve ALL A/AAAA records and reject any private/loopback/link-local/reserved/multicast/ULA address (binary check via `ipaddress` stdlib / ipaddr.js, not string match); explicit metadata denylist (169.254.169.254 + /16, fd00:ec2::254, 100.100.100.200, `::ffff:a9fe:a9fe` forms); connect pinning the validated IP; fail closed on resolution errors. Test against decimal/octal/hex/short/IPv6-mapped encodings.
67. Redirects disabled on untrusted fetches (or every hop re-validated); hard timeout ≤5s; streamed body-size cap. Node: built-in global fetch ignores `{agent}` — use got/axios/node-fetch + request-filtering-agent, or a hardened undici dispatcher. Python: stdlib pattern per the Pydantic AI 1.56.0 fix; never Advocate/SafeURL/random is-private packages.
68. Known destinations = exact-hostname allowlist (Case 1); blocklist+resolve only for genuinely arbitrary URLs (Case 2). LLM browse/fetch tools treat model URLs as attacker-controlled and preferably route through a no-secrets egress proxy (smokescreen/pipelock). Never assume Vercel blocks metadata/private ranges. Next.js middleware never calls `NextResponse.next()` reflecting raw user headers.

### K. LLM Features

69. All model output is untrusted: schema-validated structured output (`generateObject`/`streamObject` with `.max()`/enums/URL allowlists; instructor `response_model` + `extra='forbid'`); `JSON.parse(text) as T` on model output is forbidden; never `dangerouslySetInnerHTML`/eval; render as plain text or sanitized markdown. Retrieved documents and user content are data, not instructions (LLM01).
70. Each LLM tool gets the narrowest possible scope; destructive actions need human confirmation (LLM06). Per-user token/spend caps + rate limits on inference routes (LLM10, rule 36).

### L. Supply Chain & CI

71. No dependency installed without verifying the exact name on npmjs.com/PyPI (real repo, plausible downloads) — anti-slopsquatting. Lockfiles committed; CI uses `npm ci`/`--frozen-lockfile`; `npm audit --omit=dev --audit-level=high` / pip-audit in CI.
72. pnpm: `minimumReleaseAge: 4320`, `blockExoticSubdeps: true`, `trustPolicy: no-downgrade`, `allowBuilds` allowlist (never `dangerouslyAllowAllBuilds`). npm: `.npmrc` with `ignore-scripts=true`, `save-exact=true`.
73. All GitHub Actions pinned to full 40-char SHAs with `# vX.Y.Z` comments; top-level `permissions: contents: read`; `pinact run --check` in CI. *Test:* `grep -E 'uses:.*@(v[0-9]|main|master)' .github/workflows/*` → nothing.
74. `.github/dependabot.yml` covers npm (weekly, grouped), **github-actions**, and pip where present. SAST mandatory: CodeQL default setup (public) or Semgrep CE `p/typescript p/nextjs p/react` + repo-local `.semgrep/` (private), running on PRs, findings blocking.

### M. Meta-Rules for AI Sessions

75. Security-weakening diffs require explicit human approval and are never a debugging tactic: removing/disabling RLS, `USING (true)`/`WITH CHECK (true)`, deleting auth checks, `rejectUnauthorized: false`/`verify=False`, widening CORS, moving a secret client-side. A permissions error means fix the policy, not remove it.
76. Every multi-tenant feature ships with negative tests before merge: unauthenticated → 401; cross-tenant by ID → 404; member invoking admin action → denied; direct Server Action invocation without session → denied; spoofed `x-middleware-subrequest` → denied. CI runs them against a preview deploy.
77. Every incident and review finding becomes a permanent gate (Semgrep rule, pgTAP assertion, header test) — the repo-local rules directory is the institutional memory.
78. Definition of done for any feature includes its security items (policies, validation, limits, tests). If any item is skipped, say so explicitly in the PR — silence is the failure mode.
79. Key every playbook rule to OWASP Top 10:2025 IDs and ASVS 5.0 requirement numbers (from the official CSV) so each is traceable and individually testable.
80. Run Supabase Security Advisor + a passive scan pass before first production deploy and after any schema change — every table, endpoint, and JS bundle is assumed exposed until a scan proves otherwise.

---

## 6. Sources & Exemplar Repo Index

### Exemplar repositories (mimic these patterns)

| Repo | Role |
|---|---|
| https://github.com/OWASP/CheatSheetSeries | Cheat sheet sources (Authorization, Logging, File Upload, LLM sheets) |
| https://github.com/OWASP/ASVS | ASVS 5.0 requirement CSV — vendor as checklist |
| https://github.com/owasp/top10 | Top 10:2025 IDs + CWE mappings |
| https://github.com/OWASP/www-project-top-10-for-large-language-model-applications | LLM Top 10 anchor |
| https://github.com/next-safe-action/next-safe-action | authActionClient: structural auth+validation for Server Actions |
| https://github.com/t3-oss/t3-env | Build-time env validation, server/client split |
| https://github.com/upstash/ratelimit-js | Serverless rate limiting (copy examples/nextjs*) |
| https://github.com/dubinc/dub | Centralized Zod schema module at production scale |
| https://github.com/colinhacks/zod | v4 changelog = authoritative footgun record |
| https://github.com/567-labs/instructor | Pydantic-validated LLM output |
| https://github.com/stalniy/casl | Isomorphic ABAC, abilities → WHERE clauses |
| https://github.com/cerbos/cerbos · https://github.com/openfga/openfga | Policy engines (only on structural need) |
| https://github.com/usebasejump/basejump · https://github.com/usebasejump/supabase-test-helpers · https://github.com/supabase/splinter · https://github.com/supabase/dbdev | RLS patterns, pgTAP helpers, Advisor lints |
| https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/auth/third-party/clerk.mdx | Clerk-on-Supabase policy SQL |
| https://github.com/makerkit/nextjs-saas-starter-kit-lite | Current-gen Supabase migrations/policy layout |
| https://github.com/vercel/next-forge (aka haydenbleasel/next-forge) | Package composition to copy; fail-open defaults to fix |
| https://github.com/nextjs/saas-starter · https://github.com/t3-oss/create-t3-app · https://github.com/vercel/next.js/tree/canary/examples/with-supabase · https://github.com/ixartz/SaaS-Boilerplate · https://github.com/fastapi/full-stack-fastapi-template · https://github.com/zhanymkanov/fastapi-best-practices | Boilerplate survey subjects (patterns + cautionary exhibits) |
| https://github.com/vercel/vercel/tree/main/packages/firewall | @vercel/firewall checkRateLimit |
| https://github.com/arcjet/arcjet-js | @nosecone/next headers; explicit fail-mode design |
| https://github.com/marsidev/react-turnstile · https://github.com/unkeyed/unkey | CAPTCHA widget; API-key-scoped limits reference |
| https://github.com/pinojs/pino · https://github.com/getsentry/sentry-javascript · https://github.com/supabase/supa_audit | Logging, error capture, audit trigger design (vendor supa_audit SQL) |
| https://github.com/gitleaks/gitleaks · https://github.com/trufflesecurity/trufflehog · https://github.com/suzuki-shunsuke/pinact · https://github.com/bodadotsh/npm-security-best-practices · https://github.com/ossf/package-manager-best-practices · https://github.com/semgrep/semgrep-rules | Secret scanning, SHA pinning, npm hardening, SAST rules |
| https://github.com/vercel/next.js/tree/canary/examples/with-strict-csp | Canonical nonce CSP implementation |
| https://github.com/supabase/storage · https://github.com/supabase/supabase/tree/master/examples/user-management/nextjs-user-management · https://github.com/sindresorhus/file-type · https://github.com/lovell/sharp · https://github.com/ahupp/python-magic | Storage engine, upload example, magic bytes, transcoding |
| https://github.com/t3dotgg/stripe-recommendations · https://github.com/stripe-samples/subscription-use-cases · https://github.com/vercel/nextjs-subscription-payments (archived) · https://github.com/clerk/skills/blob/main/skills/features/clerk-billing/SKILL.md | Billing patterns |
| https://github.com/azu/request-filtering-agent · https://github.com/stripe/smokescreen · https://github.com/luckyPipewrench/pipelock | SSRF agent, egress proxies |

### Standards, docs & advisories

- https://owasp.org/Top10/2025/ · https://owasp.org/www-project-top-10-for-large-language-model-applications · https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html · .../File_Upload_Cheat_Sheet.html · .../Logging_Cheat_Sheet.html · .../NPM_Security_Cheat_Sheet.html
- https://nextjs.org/docs/app/guides/data-security · https://nextjs.org/docs/app/guides/content-security-policy · https://nextjs.org/blog/security-nextjs-server-components-actions
- https://supabase.com/docs/guides/database/postgres/row-level-security · .../guides/api/api-keys · .../guides/auth/third-party/clerk · .../guides/ai-tools/ai-prompts/database-rls-policies · .../guides/local-development/testing/overview · .../guides/local-development/testing/pgtap-extended · .../guides/storage/security/access-control · .../guides/storage/schema/helper-functions · .../guides/database/database-advisors · https://supabase.github.io/splinter/0010_security_definer_view/ · https://supabase.github.io/splinter/0011_function_search_path_mutable/ · https://supabase.com/docs/guides/troubleshooting/rls-performance-and-best-practices-Z5Jjwv
- https://clerk.com/docs/reference/nextjs/clerk-middleware · https://clerk.com/docs/guides/secure/authorization-checks · https://clerk.com/docs/guides/development/integrations/databases/supabase · https://clerk.com/blog/multitenancy-clerk-supabase-b2b · https://clerk.com/docs/nextjs/guides/billing/for-b2c
- https://vercel.com/blog/postmortem-on-next-js-middleware-bypass · https://vercel.com/changelog/cve-2025-57822 · https://vercel.com/docs/deployment-protection · https://vercel.com/docs/headers/response-headers · https://vercel.com/docs/functions/limitations
- https://docs.stripe.com/checkout/fulfillment · https://docs.stripe.com/webhooks · https://brandur.org/idempotency-keys
- CVE-2025-29927 analyses: https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/ · https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass
- https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-2jrp-274c-jhv3 (+ CVE-2026-46678/48782 IPv6 bypass chain, CVE-2026-8768 AI SDK, CVE-2025-9960 is-localhost-ip)
- https://semgrep.dev/p/nextjs · https://semgrep.dev/p/typescript · https://semgrep.dev/docs/semgrep-ci/overview
- https://zod.dev/v4/changelog · https://ai-sdk.dev/docs/ai-sdk-core/generating-structured-data · https://pnpm.io/supply-chain-security · https://fastapi.tiangolo.com/tutorial/request-files/

### Empirical evidence & incidents

- Veracode 2025 GenAI Code Security Report: https://www.veracode.com/blog/genai-code-security-report/ · https://www.helpnetsecurity.com/2025/08/07/create-ai-code-security-risks/
- Pearce et al., "Asleep at the Keyboard": https://arxiv.org/abs/2108.09293 · slopsquatting: https://arxiv.org/abs/2605.17062 · https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks
- CVE-2025-48757 (Lovable): https://blog.vibecoder.me/post-mortem-lovable-cve-2025-48757 · https://vibeappscanner.com/lovable-security
- Escape.tech 5,600-app scan: https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/ · Symbiotic: https://www.symbioticsec.ai/blog/we-scanned-1-072-vibe-coded-apps-98-had-security-flaws
- GitGuardian Secrets Sprawl 2026: https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ · https://www.csoonline.com/article/3953927/ai-programming-copilots-are-worsening-code-security-and-leaking-more-secrets.html
- EnrichLead shutdown: https://x.com/leojrr/status/1901560276488511759 · https://pivot-to-ai.com/2025/03/18/guys-im-under-attack-ai-vibe-coding-in-the-wild/ · https://techstartups.com/2025/03/26/when-vibe-coding-goes-wrong/
- PortSwigger single-packet races: https://portswigger.net/research/smashing-the-state-machine

**Honest gaps carried forward:** no FastAPI-specific OWASP cheat sheet exists; no canonical "security regression testing for Next.js" repo (assemble from parts); no published Clerk Billing bypass writeups (risk inferred from architecture); no named v0/Bolt breach postmortems beyond aggregate scan data; no Semgrep registry rules for Supabase Storage (write custom).
