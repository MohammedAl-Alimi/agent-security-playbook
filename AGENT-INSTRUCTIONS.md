# Agent Instructions

You are an AI coding agent (Claude Code or similar). A user has pointed you at this repo to **build a feature securely** or **audit an existing app**. Follow these steps in order. Do not skip the verification phase — it is what makes the work trustworthy.

> Read [`PLAYBOOK.md`](PLAYBOOK.md) first for the threat model behind these steps. This file is the executable summary.

---

## Step 0 — Ground rules (non-negotiable)

- **Fail closed.** An error in an auth check, validator, or rate limiter denies the request. A missing security env var crashes boot — it never silently disables protection.
- **Never weaken security to fix a bug.** Disabling RLS, adding `USING (true)`, setting CORS to `*`, or commenting out an auth check to "make it work" requires explicit human approval. Fix the policy, not the protection.
- **Verify every new dependency exists** (registry page, repo, downloads) before installing. LLMs hallucinate package names; attackers register them ([supply chain](rules/14-supply-chain.md)).
- **All external input is untrusted** — including webhook payloads, headers, searchParams, and LLM output.
- **Every security rule you apply gets a machine check** — a test, a grep, or a CI gate. If it can regress silently, you haven't finished.

## Step 1 — Install the rules into the project (once)

Copy [`templates/CLAUDE-security.md`](templates/CLAUDE-security.md) into the project's `CLAUDE.md` / `AGENTS.md` (append under a `## Security rules` heading). Every future session then inherits the rules without re-reading this repo.

## Step 2 — Map the trust boundaries

Before writing or auditing anything, enumerate:

- **Entry points**: routes, server actions, webhooks, cron handlers, WebSocket handlers.
- **Identity flow**: where sessions are created, checked, and what derives from them.
- **Data access**: which queries touch which tables; where tenant/user scoping happens (app layer and/or RLS).
- **Secrets**: every env var, which are server-only, which reach the client bundle.
- **Money & side effects**: payments, email sends, LLM calls, file writes.

For an audit, do this in parallel (one sub-agent per boundary) and have each report violations against the relevant chapter.

## Step 3 — Apply the relevant chapters

When building, open the checklist that matches the work:

- New feature → [`checklists/new-feature.md`](checklists/new-feature.md)
- New route/action/webhook → [`checklists/new-endpoint.md`](checklists/new-endpoint.md)
- Before shipping → [`checklists/pre-deploy.md`](checklists/pre-deploy.md)

Each checklist links to the [rule chapters](rules/). Read the chapters relevant to the code you're touching — every rule has a ❌/✅ pair to pattern-match against.

## Step 4 — Wire the self-verification suite

Follow [`rules/15-testing-verification.md`](rules/15-testing-verification.md). Minimum bar for any app:

1. A table-driven test asserting every mutating endpoint rejects unauthenticated (401) and cross-tenant (403/404) requests.
2. RLS tests (`supabase test db` / pgTAP) if the DB is Postgres with RLS.
3. Webhook tests: bad signature → 400; replayed event → no double fulfillment.
4. Secret scanning (gitleaks) and SAST (Semgrep) in CI, blocking on findings.

When you add a feature, **extend the suite in the same PR** — a new endpoint that isn't in the 401/403 table is a regression.

## Step 5 — Verify before claiming done

Run the full suite and the scanners. Report actual output, not intentions. If anything is red, it ships red or gets fixed — never deleted to make CI pass.
