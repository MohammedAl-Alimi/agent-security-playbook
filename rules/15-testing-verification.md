# ✅ Self-Verification & Regression Testing

Every rule in this playbook exists as a test or CI gate that FAILS on regression — because AI code fails by omission, and nobody notices an omission by reading the diff.

## TL;DR — the rules

1. Ship a negative test suite: every route and action is proven to reject unauthenticated (401) and cross-tenant (403/404) requests, table-driven from a route manifest.
2. Ship an RLS test suite: pgTAP via `supabase test db` per table, plus splinter Security Advisor lints as build-breakers.
3. Test the schemas themselves: unknown-key rejection, coercion edge cases, discriminated-union hybrids.
4. Assert security headers in CI on every PR.
5. Test webhooks adversarially: bad signature → 400, replayed event → exactly one fulfillment.
6. Test the rate limiter: the Nth+1 request in a window → 429.
7. Gate CI on secret scanning (gitleaks) and SAST (Semgrep + repo-local rules).
8. The contract: the security regression suite runs on every PR, red = merge blocked, no bypass label.
9. When adding a feature, an AI agent extends the suite first (routes → manifest, tables → pgTAP, incidents → Semgrep rules) and runs it before claiming done.
10. CI lockfile gate fails on react/react-dom/react-server-dom-* below 19.0.1/19.1.2/19.2.1 or unpatched Next.js — and re-runs on a weekly schedule, not only on PRs.

## Rule 1 — Why tests, not vigilance

Two verified findings make this chapter the capstone. Veracode (2025, 100+ LLMs): AI introduces vulnerabilities in **45% of coding tasks** — by *omission*: the missing auth check, the missing policy, the missing signature verification all pass the happy-path demo. Perry et al. (Stanford): developers using AI assistants write less secure code **and rate it as more secure**. So neither the generator nor the reviewer will catch the gap. The boilerplate survey confirms it: across six "production-ready" starters, **zero ship a single authorization test**.

The consequence: a security property that exists only in code can be silently removed by the next session; a property encoded as a failing test cannot.

**Verify:** this repo has a `test:security` script and a CI job named `security-regression` required by branch protection.

## Rule 2 — The negative suite: 401/403 for every route, table-driven

One test file enumerates every endpoint against an authorization matrix (anon / member / other-org member / admin). Enumeration is the point — a hand-picked sample misses exactly the route the AI forgot (threat-model rows #2–#5, CVE-2025-29927's durable lesson).

```ts
// ❌ WRONG — three ad-hoc tests for the routes someone remembered

// ✅ RIGHT — e2e/authz-matrix.spec.ts: manifest × roles → expected status
import { ROUTES } from './route-manifest';   // [{ path, method, body?, expect: { anon, member, otherOrg } }]
const SESSIONS = { anon: null, member: 'e2e/.auth/member.json', otherOrg: 'e2e/.auth/other-org.json' };

for (const r of ROUTES) for (const [role, state] of Object.entries(SESSIONS)) {
  test(`${r.method} ${r.path} as ${role} → ${r.expect[role]}`, async ({ browser }) => {
    const ctx = await browser.newContext(state ? { storageState: state } : {});
    const res = await ctx.request.fetch(r.path(SEED.orgA), { method: r.method, data: r.body });
    expect(res.status()).toBe(r.expect[role]);   // anon: 401; otherOrg on A's IDs: 404/403
  });
}

// Completeness tripwire: the manifest may not silently rot
test('manifest covers the app', async () => {
  const discovered = await globRoutes('app/api/**/route.ts', 'app/**/actions.ts');
  expect(new Set(ROUTES.map(r => r.key))).toEqual(new Set(discovered));
});
```

Include the middleware-bypass probe: the same requests with `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` must still be denied. Server Actions are invoked directly (they are public POST endpoints) — no browser required. Cross-tenant rows use seeded fixture accounts A and B requesting each other's real resource IDs.

**Verify:** delete the `auth()` call from any handler → at least one matrix cell goes red; the completeness test fails when a new route ships without a manifest entry.

## Rule 3 — RLS tests: pgTAP + splinter in CI

App-layer tests can't see a policy gap the app never exercises (the DELETE nobody wired up, the UPDATE that lets `owner_id` be reassigned). Test the database directly — `supabase test db` runs pgTAP from `supabase/tests/`, and supabase-test-helpers provides the actor plumbing.

```sql
-- ✅ RIGHT — supabase/tests/tasks_rls.test.sql
begin;
select plan(4);
select tests.rls_enabled('public');                    -- one tripwire for the whole schema
select tests.create_supabase_user('alice');
select tests.create_supabase_user('mallory');
select tests.authenticate_as('alice');
insert into tasks (title) values ('mine');
select tests.authenticate_as('mallory');
select is_empty($$ select * from tasks $$, 'cross-tenant SELECT sees nothing');   -- empty, not error!
select results_eq($$ update tasks set title = 'stolen' returning 1 $$, $$ values (1) offset 1 $$,
                  'cross-tenant UPDATE affects zero rows');
select * from finish(); rollback;
```

Deny tests assert **empty results, not errors** — `auth.uid()` is NULL for anon, so a broken policy filters silently. Run splinter Security Advisor lints in the same job; treat `rls_disabled_in_public`, `policy_exists_rls_disabled`, `security_definer_view`, `auth_users_exposed`, `function_search_path_mutable`, `rls_references_user_metadata` as build-breaking. This is what CVE-2025-48757 (170+ breached Lovable apps, tables world-readable via the shipped anon key) makes non-optional.

**Verify:** `supabase test db` runs on every migration PR; creating a table without RLS in a migration turns `tests.rls_enabled('public')` red.

## Rule 4 — Schema, header, webhook, and rate-limit regression tests

Each earlier chapter ends in a machine check; this suite is where they live. The four that catch the most AI regressions:

```ts
// ✅ Schemas (ch. 03): valid / mass-assignment / coercion fixtures
expect(() => TaskCreate.parse({ ...valid, role: 'admin' })).toThrow();     // strictObject holds
expect(Query.safeParse({ public: 'false' }).data?.public).toBe(false);     // stringbool, not coerce.boolean
expect(Query.safeParse({ limit: '' }).success).toBe(false);               // '' must not become 0

// ✅ Webhooks (ch. 08/12): forged signature and replay
await expect(post('/api/webhooks/stripe', payload, { sig: 'bad' })).resolves.toHaveStatus(400);
await post('/api/webhooks/stripe', signed);         // replay the identical signed event
await post('/api/webhooks/stripe', signed);
expect(await count('fulfillments')).toBe(1);        // idempotency held

// ✅ Rate limits (ch. 06): the limiter is actually wired to the route
const results = await Promise.all(range(N + 1).map(() => post('/api/expensive', body)));
expect(results.filter(r => r.status === 429).length).toBeGreaterThan(0);
expect(results.find(r => r.status === 429)?.headers['retry-after']).toBeDefined();
```

Headers are asserted per [10 — Headers, CSP & CORS](./10-headers-csp-cors.md) Rule 6 against a production build. Add the payments red-team items from [12](./12-payments.md): forged success redirect, tampered price, parallel credit double-spend (10 concurrent spends → granted ≤ balance).

**Verify:** each of the four blocks exists in `test:security`; commenting out the limiter, the signature check, or `strictObject` turns a named test red.

## Rule 5 — Secret scanning and SAST as merge gates

AI-assisted commits leak secrets at **more than twice** the human rate (GitGuardian 2026: 3.2% vs 1.5%). Scanners are cheap, deterministic, and catch what review doesn't read.

```yaml
# ✅ RIGHT — .github/workflows/security.yml (SHA-pin real versions; tags are how tj-actions burned 23k repos)
permissions: { contents: read }
jobs:
  secrets:
    steps:
      - uses: actions/checkout@<40-char-sha>   # v5.0.0 — with fetch-depth: 0
      - uses: gitleaks/gitleaks-action@<40-char-sha>   # v3
  sast:
    steps:
      - run: semgrep ci --config p/typescript --config p/nextjs --config p/react --config .semgrep/
```

The repo-local `.semgrep/` directory is the institutional memory: every incident and review finding becomes a permanent rule (this playbook's greps — `passthrough` on inbound schemas, `coerce.boolean`, interpolated logger calls, `process.env.` outside `env.ts`, `service_role` outside the server-only module — belong here as executable rules, not prose). Enable GitHub push protection; a committed secret means **rotate at the provider**, never just delete the commit.

**Verify:** push a fake AWS key on a test branch → CI fails; `grep -E 'uses:.*@(v[0-9]|main|master)' .github/workflows/*` → nothing (SHAs only).

## Rule 6 — The contract, and how an agent extends it

The contract in one sentence: **the security regression suite runs on every PR, and red blocks merge** — branch protection requires the `security-regression` job; there is no skip label, and weakening a test is a security-weakening diff requiring explicit human approval (never a debugging tactic).

When an AI agent adds a feature, the suite is part of the feature — extend it *before* claiming done:

1. New route/action → add its row to the route manifest (the completeness test forces this).
2. New table/migration → add its pgTAP file: owner CRUDs own rows; non-owner sees empty and cannot write; anon sees only intended-public rows.
3. New schema → add valid / +`role:"admin"` / coercion-edge fixtures.
4. New webhook/payment path → add forged-signature and replay tests.
5. New expensive endpoint → add its 429 test.
6. Run `npm run test:security` (and `supabase test db` if migrations changed) and paste the passing output in the PR. If any item is skipped, say so explicitly — silence is the failure mode.

**Verify:** PR template contains this checklist; branch protection lists `security-regression` as required; `git log` shows no merge commits with the job red.

## Rule 7 — Lockfile version gate for known-RCE framework lines

React2Shell (CVE-2025-55182, CVSS 10.0 unauthenticated RCE in RSC flight deserialization) plus Next.js CVE-2025-66478 made the *default* create-next-app build remotely exploitable, with in-the-wild exploitation within days. Only a lockfile-level floor catches the vulnerable transitive `react-server-dom-*` copy that a later upgrade or dedupe quietly reintroduces — and only a scheduled run catches an advisory published when no PR is open.

```yaml
# ✅ RIGHT — version-gate job runs on PRs AND a weekly schedule
on:
  pull_request: {}
  schedule: [{ cron: "0 6 * * 1" }]
# gate step parses the lockfile and fails on any of:
#   react / react-dom / react-server-dom-{webpack,turbopack,parcel}
#     < 19.0.1 (19.0.x line) / < 19.1.2 (19.1.x) / < 19.2.1 (19.2.x)
#   next below the CVE-2025-66478-patched release for its line
#   next < 15.2.3 / @clerk/nextjs < 6.39.2 (the ch01 Rule 2 floors)
```

A red weekly run has an owner: it triggers the same-week-deploy policy in [01 — Authentication](./01-authentication.md) Rule 7.

**Verify:** pin `react-server-dom-webpack@19.0.0` on a test branch → the gate job fails; the workflow file contains a `schedule:` trigger for this job.

---

This is the capstone — every chapter's `**Verify:**` line lands in this suite. Start at [01 — Auth & Authorization](./01-auth-and-authorization.md) · [03 — Input Validation](./03-input-validation.md) · [09 — Logging & Errors](./09-logging-and-errors.md) · [12 — Payments](./12-payments.md)
