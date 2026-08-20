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

### Input
4. Parse all external input (body, params, searchParams, headers, webhooks, LLM output) through a strict schema (`z.strictObject()` / Pydantic `extra='forbid'`) before use. Never spread raw input into a DB write.
5. Validate env vars at boot; a missing security-critical var fails the build/boot, never silently disables a protection.

### Data
6. Every new table gets RLS enabled + full policies (incl. WITH CHECK and DELETE) in the same migration that creates it.
7. Service-role/admin DB credentials live only in `server-only` modules. Parameterized queries only.
8. Counters, credits, and quotas change via atomic conditional updates (`UPDATE ... WHERE balance >= x RETURNING`), never read-modify-write.

### Credentials & tokens
9. Passwords: Argon2id (or bcrypt cost ≥ 10), hashed server-side. Never MD5/SHA-x, never client-side-only hashing.
10. Tokens (API keys, reset, verification, refresh): generated with `crypto.randomBytes(32)`+ (never `Math.random()`), stored only as hashes, single-use, short TTL.
11. All secret/signature comparisons are timing-safe (`crypto.timingSafeEqual`).
12. JWTs: allowlist algorithms, verify `exp`/`aud`/`iss`, access tokens ≤ 15 min, refresh rotation with reuse detection. Session cookies: httpOnly + secure + sameSite.

### Side effects
13. Webhooks: verify signature over the raw body before parsing; missing signing secret = boot failure; processing idempotent on event ID.
14. Payments: fulfill only from verified webhooks (never `?success=true`), re-fetch state from the provider, amounts/prices server-side only.
15. Rate limit auth, email, LLM, and payment routes with a global store (not in-memory), keyed on `userId ?? ip`, failing closed.
16. Never fetch a user- or model-supplied URL without the SSRF validator (scheme allowlist, private-IP block, redirects off).
17. Uploads: magic-byte type check, server-side size cap, randomized keys, private buckets + signed URLs.

### Hygiene
18. Errors to clients: generic message + request ID only. Catch blocks around security checks fail closed. Structured logs with PII/secret redaction; never interpolate raw user input into log strings.
19. Nothing secret ever carries a client env prefix (`NEXT_PUBLIC_`, `VITE_`). gitleaks runs pre-commit and in CI.
20. Verify every new dependency on the registry before installing (LLM-hallucinated names get typosquatted). Commit lockfiles; CI installs frozen.

### Meta
21. Never weaken a security control (disable RLS, `USING (true)`, CORS `*`, comment out auth) to fix a bug — flag for human approval instead.
22. Every new endpoint is added to the 401/unauthenticated + cross-tenant negative test table in the same PR. Security tests red = merge blocked.
