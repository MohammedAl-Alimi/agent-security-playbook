<p align="center">
  <img src="assets/banner.svg" alt="Agent Security Playbook — defense-in-depth rules for AI-generated applications" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-5eead4.svg"></a>
  <img alt="Works with any AI agent" src="https://img.shields.io/badge/works%20with-any%20AI%20agent-a78bfa.svg">
  <img alt="15 rule chapters" src="https://img.shields.io/badge/rules-15%20chapters-38bdf8.svg">
</p>

<p align="center">
  <sub><b>COMPATIBLE WITH</b></sub><br>
  <img alt="Claude Code" src="https://img.shields.io/badge/Claude_Code-D97757?logo=claude&logoColor=white">
  <img alt="OpenAI Codex" src="https://img.shields.io/badge/OpenAI_Codex-412991?logo=openai&logoColor=white">
  <img alt="Cursor" src="https://img.shields.io/badge/Cursor-000000?logo=cursor&logoColor=white">
  <img alt="GitHub Copilot" src="https://img.shields.io/badge/GitHub_Copilot-000000?logo=githubcopilot&logoColor=white">
  <img alt="Gemini CLI" src="https://img.shields.io/badge/Gemini_CLI-1C69FF?logo=googlegemini&logoColor=white">
</p>

# Agent Security Playbook

**Defense-in-depth security rules that AI coding agents can follow — and verify.**

Point any AI coding agent (Claude Code, Cursor, Copilot, etc.) at this repo and say *"follow the instructions here to secure my app"* (or *"...to build this feature securely"*), and it will apply a research-backed, testable rule set instead of shipping the happy path.

---

## Why this exists

AI-generated ("vibe-coded") applications don't fail because the model writes broken crypto. They fail because the model **silently omits** the security layer: the RLS policy, the authorization check, the rate limiter, the webhook signature, the password hash. The feature still works in the demo — and that's exactly the problem.

The evidence (all sources in [`research/`](research/security_and_replication_findings.md)):

- Veracode's 2025 GenAI report: LLMs introduce vulnerabilities in **~45% of coding tasks** — and newer models improved at syntax, *not* security.
- GitGuardian: AI-assisted commits leak secrets at **more than 2× the human rate**.
- CVE-2025-48757: **170+ vibe-coded apps breached** through Supabase tables created without Row-Level Security.
- CVE-2025-29927: Next.js middleware-only auth **bypassed with a single spoofed header**.
- Stanford: developers using AI assistants wrote *less* secure code while rating it as *more* secure.

Reminders don't fix omission. **Structure does.** Every rule in this playbook is phrased as a testable imperative with a machine check — a test, a grep, or a CI gate — so a regression turns the build red instead of relying on anyone's vigilance.

---

## What you get

1. **[15 rule chapters](rules/)** — concrete DO/DON'T patterns for every layer, each rule with a ❌/✅ code pair and a **Verify** step.
2. **[Agent instructions](AGENT-INSTRUCTIONS.md)** — the executable entry point: what an agent does step by step to build or audit securely.
3. **[The playbook](PLAYBOOK.md)** — the threat model and reasoning behind the rules.
4. **[A drop-in rules file](templates/CLAUDE-security.md)** — paste into your project's `CLAUDE.md` / `AGENTS.md` so every future session inherits the rules.
5. **[Checklists](checklists/)** — new feature, new endpoint, pre-deploy.
6. **[The research corpus](research/security_and_replication_findings.md)** — every CVE, incident, study, and exemplar repo the rules are built on.

Everything is generic-first: examples use Next.js / Supabase / Clerk / Stripe because they're common, but the patterns apply to any stack.

---

## The rules

| # | Chapter | The one-line version |
|---|---------|----------------------|
| 01 | [🔑 Authentication](rules/01-authentication.md) | Auth in every handler — middleware is never the boundary. |
| 02 | [🛡️ Authorization & RBAC](rules/02-authorization.md) | Every query that takes an ID also filters by the caller's identity. |
| 03 | [🧪 Input Validation](rules/03-input-validation.md) | Parse, don't validate — strict schemas at every trust boundary. |
| 04 | [🗄️ Database & RLS](rules/04-database-rls.md) | RLS on every table, in the same migration that creates it. |
| 05 | [🔐 Secrets & Environment](rules/05-secrets-and-env.md) | Secrets are structurally quarantined, scanned, and never client-prefixed. |
| 06 | [🔒 Hashing, Tokens & Credentials](rules/06-hashing-and-tokens.md) | Argon2id server-side; store only hashes; timing-safe compares; short-lived tokens. |
| 07 | [⏱️ Rate Limiting](rules/07-rate-limiting.md) | Global-store limits on every expensive route, failing closed. |
| 08 | [📨 Webhooks](rules/08-webhooks.md) | Verify the signature over the raw body first; missing secret = boot failure. |
| 09 | [📋 Logging & Errors](rules/09-logging-and-errors.md) | Generic errors out, structured redacted logs in, fail closed in catch. |
| 10 | [🧱 Headers, CSP & CORS](rules/10-headers-csp-cors.md) | Nonce-based CSP, exact-origin CORS, hardened cookies. |
| 11 | [📁 File Uploads](rules/11-file-uploads.md) | Magic-byte checks, private buckets, randomized keys, re-encode images. |
| 12 | [💳 Payments](rules/12-payments.md) | Fulfill from verified webhooks only — never from a redirect. |
| 13 | [🤖 SSRF & LLM Apps](rules/13-ssrf-and-llm.md) | Never fetch a user- or model-supplied URL raw; LLM output is untrusted input. |
| 14 | [📦 Supply Chain](rules/14-supply-chain.md) | Verify every package exists before installing; pin, lock, scan. |
| 15 | [✅ Self-Verification](rules/15-testing-verification.md) | Security regressions must turn CI red — negative tests for every rule. |

---

## How to use it

**With an AI agent** — point it here:

> Read https://github.com/MohammedAl-Alimi/agent-security-playbook and follow AGENT-INSTRUCTIONS.md to audit this project / build this feature.

**As a project default** — copy [`templates/CLAUDE-security.md`](templates/CLAUDE-security.md) into your project's `CLAUDE.md` (or `AGENTS.md`), so every future session starts with the rules loaded.

**As a human** — read [`PLAYBOOK.md`](PLAYBOOK.md) for the threat model, then keep the [checklists](checklists/) next to your code review.

---

## License

[MIT](LICENSE). Use it, fork it, ship safer apps.
