# 🔭 AI Security Watch

A daily-updated log of new vulnerabilities, breaches, and research affecting AI-generated ("vibe-coded") applications. Maintained by a scheduled Claude cloud agent; every entry is verified against a primary source before it lands here.

**Last checked:** 2026-08-20 — check in progress.

---

## How this file is updated

- A cloud agent runs once a day. It searches for incidents, CVEs, and research from the last few days that affect AI-generated apps (missing auth/RLS, leaked secrets, supply-chain attacks, prompt injection, framework CVEs).
- New, verified findings are **appended** to the log below, each with a source URL.
- A finding that should change one of the [rule chapters](rules/) is flagged with **⚠ PROPOSED RULE UPDATE** and the chapter number, for human review — the agent never edits the chapters itself.
- If nothing new and verifiable turns up, only the **Last checked** line above is updated.

---

## Log

### 2026-08-20 — baseline

- Repo launched. The founding research corpus (CVEs, breach postmortems, and studies through this date) lives in [`research/security_and_replication_findings.md`](research/security_and_replication_findings.md).
