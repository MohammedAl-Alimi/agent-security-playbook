# Security rules (drop-in for CLAUDE.md / AGENTS.md)

<!-- Paste everything below into your project's CLAUDE.md or AGENTS.md.
     Full rationale, code patterns, and verification recipes:
     https://github.com/MohammedAl-Alimi/agent-security-playbook -->

## Security rules

These rules are mandatory for all code in this project. Full patterns: [agent-security-playbook](https://github.com/MohammedAl-Alimi/agent-security-playbook).

### Identity & access
1. Every route handler, server action, and data-layer function performs its own auth check. Middleware is redirect UX, never the security boundary.
2. Every query that takes an object ID also filters by the caller's identity (or tenant). Return 404 on zero rows. "Is logged in" is not authorization.
3. Roles, user IDs, org IDs, and prices are derived from the session or server — never accepted from a request body.
4. Federated login: Authorization Code + PKCE, exact-match redirect URIs, link accounts by immutable `sub` never by email; `returnTo`/`next` params validated as same-origin paths; magic links stored hashed, short-lived, consumed via POST; session ID regenerated on every privilege change.

### Input
5. Parse all external input (body, params, searchParams, headers, webhooks, LLM output) through a strict schema (`z.strictObject()` / Pydantic `extra='forbid'`) before use. Never spread raw input into a DB write.
6. Validate env vars at boot; a missing security-critical var fails the build/boot, never silently disables a protection.

### Output & rendering
7. innerHTML-family sinks (`dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`) are banned on user- or third-party-derived data; legitimate rich HTML flows through ONE sanctioned sanitizer module; user-supplied URLs in href/src pass a scheme allowlist (no `javascript:`/`data:`); LLM/markdown output renders with HTML disabled.

### Data
8. Every new table gets RLS enabled + full policies (incl. WITH CHECK and DELETE) in the same migration that creates it.
9. Service-role/admin DB credentials live only in `server-only` modules. Parameterized queries only.
10. Counters, credits, and quotas change via atomic conditional updates (`UPDATE ... WHERE balance >= x RETURNING`), never read-modify-write.

### Business logic
11. Multi-step flows are server-side state machines: status enum + allowed transitions, advanced in one transaction with rowcount check; status fields never client-settable; derived values (totals, discounts) recomputed server-side.
12. One-shot semantics (trials, coupons, invites, votes) enforced with DB UNIQUE constraints, never check-then-insert; feature flags are rollout tools, never authorization.

### Credentials & tokens
13. Passwords: Argon2id (or bcrypt cost ≥ 10), hashed server-side. Never MD5/SHA-x, never client-side-only hashing.
14. Tokens (API keys, reset, verification, refresh): generated with `crypto.randomBytes(32)`+ (never `Math.random()`), stored only as hashes, single-use, short TTL.
15. All secret/signature comparisons are timing-safe (`crypto.timingSafeEqual`).
16. JWTs: allowlist algorithms, verify `exp`/`aud`/`iss`, access tokens ≤ 15 min, refresh rotation with reuse detection. Session cookies: httpOnly + secure + sameSite.

### Side effects
17. Webhooks: verify signature over the raw body before parsing; missing signing secret = boot failure; processing idempotent on event ID.
18. Payments: fulfill only from verified webhooks (never `?success=true`), re-fetch state from the provider, amounts/prices server-side only.
19. Rate limit auth, email, LLM, and payment routes with a global store (not in-memory), keyed on `userId ?? ip`, failing closed.
20. Never fetch a user- or model-supplied URL without the SSRF validator (scheme allowlist, private-IP block, redirects off).
21. Uploads: magic-byte type check, server-side size cap, randomized keys, private buckets + signed URLs.
22. Caching: authenticated/personalized responses are `Cache-Control: private, no-store`; any server-side cache entry holding user data includes the user/tenant ID in its key; never cache an authorization or entitlement decision.
23. Email: reject `\r\n` in header-bound fields, HTML-escape every interpolated value, recipients from DB not request bodies; email/phone change requires fresh re-auth, confirmation on the NEW address, and notification of the OLD one; DMARC enforced on the sending domain.
24. Realtime: authenticate the WebSocket/SSE handshake itself with an exact-origin allowlist; Supabase Realtime channels are `private: true` with RLS on `realtime.messages`; postMessage uses exact-match origins and validated payloads.

### Agents & AI
25. No agent context combines private-data reads + untrusted-content ingestion + external egress; MCP servers are credentialed dependencies (verified source, pinned version, hashed tool descriptions, one scoped credential each); RAG retrieval runs AS the requesting user (vector store under RLS/tenant filters); agent memory is schema-validated on write and untrusted on read.

### Client data
26. Production/client data never enters the repo: fixtures and seeds use Faker-generated or export-time-anonymized data; data-shaped artifacts (`*.csv`, `*.sqlite*`, `*.dump`, `*.log`, `data/`) are gitignored, and notebooks are output-stripped (nbstripout).
27. PII never goes in logs (do-not-log list enforced by logger redaction), URLs, localStorage, client bundles, error-tracker events (`sendDefaultPii` off + scrubber), or LLM prompts (minimize + pseudonymize first).
28. Prod data stays in prod: dev/staging/CI use anonymized dumps; retention is a scheduled deletion job; deletion requests fan out to every third party holding copies.

### Hygiene
29. Errors to clients: generic message + request ID only. Catch blocks around security checks fail closed. Structured logs with PII/secret redaction; never interpolate raw user input into log strings.
30. Nothing secret ever carries a client env prefix (`NEXT_PUBLIC_`, `VITE_`). gitleaks runs pre-commit and in CI.
31. Verify every new dependency on the registry before installing (LLM-hallucinated names get typosquatted). Commit lockfiles; CI installs frozen.

### Operations
32. Security events page a human: alerts on auth-failure spikes and mass exports, canary tokens planted and mapped in the incident runbook, offsite backups with quarterly restore tests.
33. Deployment: preview URLs behind deployment protection, one platform instance per environment with a boot assertion failing prod on test keys, containers non-root and digest-pinned, DNS records removed before project deletion, debug/docs endpoints off in prod.

### Meta
34. Never weaken a security control (disable RLS, `USING (true)`, CORS `*`, comment out auth) to fix a bug — flag for human approval instead.
35. Every new endpoint is added to the 401/unauthenticated + cross-tenant negative test table in the same PR. Security tests red = merge blocked.
