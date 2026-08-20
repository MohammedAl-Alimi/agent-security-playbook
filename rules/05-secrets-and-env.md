# 🔐 Secrets & Environment

Secrets are protected by structure (build failures, quarantine modules, scanners), never by carefulness — AI-assisted commits leak secrets at more than 2x the human rate, so every guardrail here is a machine gate.

## TL;DR — the rules

1. Validate all env vars at build time with a single typed env module (t3-env or equivalent); a missing secret fails the build.
2. Never put a secret in a `NEXT_PUBLIC_`/`VITE_` var — those are inlined into the client bundle and public forever.
3. Read privileged keys (service-role, admin API keys) in exactly one module that starts with `import 'server-only'`.
4. Gitignore `.env*` before the first commit; commit `.env.example` with every key name and no values.
5. Run secret scanning in three layers: gitleaks pre-commit, gitleaks + TruffleHog in CI, GitHub push protection on.
6. A leaked secret is rotated at the provider immediately — deleting the commit is never enough.
7. Never log secrets: redact `authorization`, `cookie`, `*.token`, `*.apiKey`, `*.secret` paths; never log `process.env`.
8. Use separate keys per environment (dev/preview/prod) with the least-privilege scope each key needs.

## Rule 1 — One typed env module, validated at build time

**Why:** The most common fail-open bug in production starters is a missing security env var silently disabling protection — next-forge's `packages/security` no-ops without `ARCJET_KEY`, and its Stripe webhook returns HTTP 200 "Not configured" without `STRIPE_WEBHOOK_SECRET`, so Stripe never retries and billing events vanish. Boot-time validation turns those into build failures.

```ts
// ❌ WRONG — scattered, unvalidated, fails open at runtime
const key = process.env.RESEND_API_KEY!; // undefined in prod → crash or silent no-op

// ✅ RIGHT — src/env.ts, imported in next.config.ts so the BUILD fails
import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  server: {
    SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
    RESEND_API_KEY: z.string().min(1),
    STRIPE_WEBHOOK_SECRET: z.string().min(1),
  },
  client: {
    NEXT_PUBLIC_SUPABASE_URL: z.url(),
  },
  runtimeEnv: {
    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
    RESEND_API_KEY: process.env.RESEND_API_KEY,
    STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
  },
  emptyStringAsUndefined: true,
});
```

Python: pydantic-settings `BaseSettings` instantiated at module import, with a `model_validator` that raises on placeholder secrets outside development (the fail-closed pattern from full-stack-fastapi-template — the only starter surveyed that does this).

**Verify:** delete a required var and run `next build` → it fails; `grep -rn 'process\.env\.' src/ app/` hits only `env.ts`; `SKIP_ENV_VALIDATION` is unset in every deployment environment.

## Rule 2 — `NEXT_PUBLIC_` / `VITE_` means published to the world

**Why:** These prefixes inline the value into the static client bundle at build time. Anyone can read it forever, including from old deployments. Allowed public vars: Supabase URL + publishable key, Clerk publishable key, site URL, analytics IDs. Never: service-role keys, secret API keys, webhook secrets, Redis tokens.

```ts
// ❌ WRONG — "makes the fetch work", ships the secret to every browser
NEXT_PUBLIC_OPENAI_API_KEY=sk-...

// ✅ RIGHT — secret stays server-side; the client calls YOUR route
// app/api/generate/route.ts (server) reads env.OPENAI_API_KEY and proxies
```

**Verify:** after `next build`, `grep -r 'sb_secret\|service_role\|sk-' .next/static/` is empty; no `NEXT_PUBLIC_*`/`VITE_*` name matches `/secret|service|private|api_key/i`.

## Rule 3 — Quarantine privileged keys behind `import 'server-only'`

**Why:** A service-role key (Supabase `sb_secret_*`/legacy service_role) bypasses RLS entirely. If any client component transitively imports the module that reads it, the bundler will happily ship it. `import 'server-only'` makes that import a build error.

```ts
// ❌ WRONG — importable from anywhere, including client components
export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);

// ✅ RIGHT — lib/supabase-admin.ts: the ONLY file that touches the key
import "server-only";
import { createClient } from "@supabase/supabase-js";
import { env } from "@/env";

export function createAdminClient() {
  // callers: webhooks, cron, admin jobs only — never middleware/edge.
  // every callsite must scope by org/user itself: RLS is bypassed here.
  return createClient(env.NEXT_PUBLIC_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
}
```

**Verify:** `grep -rln 'SERVICE_ROLE' src/ | grep -v 'supabase-admin'` is empty; the quarantine file's first import is `server-only`.

## Rule 4 — `.env` gitignored, `.env.example` committed

**Why:** GitGuardian's 2026 Secrets Sprawl report ties the leak wave directly to AI-generated commits (3.2% of AI-assisted commits leak a secret vs 1.5% human; 6.4% with Copilot). The `.gitignore` entry must exist before the first commit — history is forever.

```gitignore
# ✅ RIGHT
.env*
!.env.example
```

```bash
# ✅ .env.example — names + annotations, never values
SUPABASE_SERVICE_ROLE_KEY=   # server-only, bypasses RLS, quarantined in lib/supabase-admin.ts
RESEND_API_KEY=              # server-only
NEXT_PUBLIC_SUPABASE_URL=    # public, safe in bundle
```

**Verify:** `git ls-files | grep -E '\.env'` returns only `.env.example`.

## Rule 5 — Three-layer secret scanning, non-negotiable

**Why:** With AI writing >2x leakier commits, scanning is infrastructure, not hygiene. Layers: (1) gitleaks pre-commit hook catches it before it enters history; (2) CI runs `gitleaks-action` (with `fetch-depth: 0` to scan full history) plus TruffleHog with `--results=verified,unknown`, which live-verifies 700+ credential types and exits 183 on an active credential — the right blocking signal; (3) GitHub push protection is server-side and un-skippable.

```yaml
# ✅ RIGHT — .github/workflows/secrets.yml (pin actions by SHA, see rules/14)
- uses: actions/checkout@<full-sha> # v5.0.0
  with: { fetch-depth: 0 }
- uses: gitleaks/gitleaks-action@<full-sha> # v3
- run: trufflehog git file://. --results=verified,unknown --fail
```

**Verify:** commit a seeded fake AWS key on a test branch → pre-commit blocks it, and CI fails if the hook is bypassed.

## Rule 6 — Any suspected leak = rotate immediately

**Why:** A secret that touched a commit, a chat transcript, a URL, a client bundle, or a log is compromised — scrapers index public GitHub in seconds. Rewriting history does not un-leak it. The EnrichLead shutdown and CVE-2025-48757 (170+ breached Lovable apps via exposed keys/tables) show how fast exposed credentials get exploited.

```text
❌ WRONG: git rebase -i / force-push to remove the commit, done.
✅ RIGHT: 1) rotate the key at the provider  2) redeploy with the new key
          3) audit provider logs for use during the exposure window  4) then clean history.
```

**Verify:** incident runbook exists in the repo; the old key is confirmed revoked at the provider (a call with it returns 401).

## Rule 7 — Never log secrets

**Why:** Log drains, error trackers, and `console.log(evt.data)` in webhook handlers are the second life of a leak. OWASP Logging Cheat Sheet: never log session IDs, tokens, passwords, connection strings, or `process.env`.

```ts
// ❌ WRONG
console.log("webhook received", req.headers, body);

// ✅ RIGHT — pino with explicit redaction paths
const logger = pino({
  redact: { paths: ["req.headers.authorization", "req.headers.cookie",
    "*.password", "*.token", "*.apiKey", "*.secret"], censor: "[REDACTED]" },
});
logger.info({ evtType: evt.type, evtId: evt.data.id }, "webhook received");
```

**Verify:** grep production logs for a known key prefix (`sk-`, `sb_secret`, `whsec_`) → zero hits; every `pino()` call site sets `redact`.

## Rule 8 — Per-environment keys, least-privilege scopes

**Why:** One key shared across dev/preview/prod means a preview leak is a prod breach, and rotation takes everything down at once. Scoped keys bound the blast radius.

```text
❌ WRONG: prod SUPABASE_SERVICE_ROLE_KEY pasted into .env.local and Vercel preview.
✅ RIGHT: separate Supabase project (or at minimum separate keys) per environment;
          Vercel env vars marked Sensitive and scoped per environment;
          local sync only via `vercel env pull .env.local`;
          prefer sb_publishable_*/sb_secret_* keys (legacy JWT keys deprecated end of 2026).
```

**Verify:** provider dashboards show distinct keys per environment; every Vercel secret is marked Sensitive; `vercel env ls` shows no prod-scoped secret exposed to preview.

---

Related: [14 — Supply Chain](14-supply-chain.md) (scanner CI wiring, SHA-pinned actions) · [07 — Rate Limiting](07-rate-limiting.md) (fail-closed on missing security env).
