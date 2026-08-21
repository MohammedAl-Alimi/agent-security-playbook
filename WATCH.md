# 🔭 AI Security Watch

A daily-updated log of new vulnerabilities, breaches, and research affecting AI-generated ("vibe-coded") applications. Maintained by a scheduled Claude cloud agent; every entry is verified against a primary source before it lands here.

**Last checked:** 2026-08-21 — check in progress.

---

## How this file is updated

- A cloud agent runs once a day. It searches for incidents, CVEs, and research from the last few days that affect AI-generated apps (missing auth/RLS, leaked secrets, supply-chain attacks, prompt injection, framework CVEs).
- New, verified findings are **appended** to the log below, each with a source URL.
- A finding that should change one of the [rule chapters](rules/) is flagged with **⚠ PROPOSED RULE UPDATE** and the chapter number, for human review — the agent never edits the chapters itself.
- If nothing new and verifiable turns up, only the **Last checked** line above is updated.
- The routine that maintains this file follows the [Agent Routines Playbook](https://github.com/MohammedAl-Alimi/agent-routines-playbook) (security-advisory-watch recipe).

---

## Log

### 2026-08-20 — baseline

- Repo launched. The founding research corpus (CVEs, breach postmortems, and studies through this date) lives in [`research/security_and_replication_findings.md`](research/security_and_replication_findings.md).

### 2026-08-20

- **isolated-vm sandbox escape (GHSA-864f-rcv7-6rh4):** A critical type-confusion bug in `ExternalCopy`'s `transferList` handling lets untrusted JavaScript running inside an isolate corrupt host memory for a full guest-to-host escape; all versions ≤ 7.0.0 are affected, patched in 6.2.0 and 7.0.1. Matters for AI-built apps because agent frameworks and code-execution tools commonly run model-generated or user-supplied JS inside isolated-vm, so an escape turns that sandbox into host RCE. [Endor Labs advisory](https://www.endorlabs.com/learn/ghsa-864f-rcv7-6rh4-critical-type-confusion-vulnerability-in-isolated-vm)
  - ⚠ PROPOSED RULE UPDATE (chapter 13): note that JS sandboxes used to run LLM/agent-generated code (e.g. isolated-vm) are escapable and must be patched and treated as defense-in-depth, not a trust boundary.
- **@logto/tunnel path traversal (CVE-2026-63188):** The Logto CLI tunnel serves custom sign-in experience assets from `--experience-path`, but `../` segments in a static-asset request let an unauthenticated requester read files outside that directory that the CLI process can read (High, CVSS 8.7); fixed in 0.3.9. Matters for AI-built apps that wire up Logto for authentication and run the dev tunnel, since it can leak local files (including secrets) while reachable. [GitLab advisory (CVE-2026-63188)](https://advisories.gitlab.com/npm/@logto/tunnel/CVE-2026-63188/)
  - ⚠ PROPOSED RULE UPDATE (chapter 03): reinforce that any static-file endpoint must normalize and reject `../` traversal before resolving a path, including in dev/CLI tooling that serves assets.

### 2026-08-21

- **@ai-sdk/harness-cline sandbox path traversal (GHSA-222v-gj5h-ff73):** The Cline harness's file tools (read, write, edit, grep, glob, ls) failed to restrict access to the session working directory and had insufficient symlink restrictions, letting a manipulated request reach files outside the sandbox, including other sessions' files (High, CVSS 7.7); affects `@ai-sdk/harness-cline` ≤ 1.0.7, fixed in 1.0.8. Matters for AI-built apps because a prompt-injected or manipulated agent could read another session's env vars, credentials, and config, or corrupt files across workspace boundaries in allow-edits mode. [GitHub advisory GHSA-222v-gj5h-ff73](https://github.com/vercel/ai/security/advisories/GHSA-222v-gj5h-ff73)
  - ⚠ PROPOSED RULE UPDATE (chapter 13): note that agent-harness file tools must canonicalize/resolve real paths and reject symlink escapes before touching the filesystem, not just check the input path string.
- **@ai-sdk/harness-opencode unauthenticated loopback control API (GHSA-vmqp-7rwf-cq3w):** The OpenCode harness's loopback HTTP control server starts with no authentication, so untrusted code running in the same sandbox can call the control API to inject prompts into the active session and make the host HarnessAgent execute attacker-chosen host tools (Moderate, CVSS 6.3); affects `@ai-sdk/harness-opencode` ≤ 1.0.72, fixed in 1.0.73. Matters for AI-built apps using this harness with host-provided tools and the default non-interactive approval policy, since it can turn sandboxed code execution into unauthorized secret lookups, deployments, or cloud API calls. [GitHub advisory GHSA-vmqp-7rwf-cq3w](https://github.com/vercel/ai/security/advisories/GHSA-vmqp-7rwf-cq3w)
  - ⚠ PROPOSED RULE UPDATE (chapter 13): require that any loopback/local control API exposed by an agent harness be authenticated, not just network-local, since sandboxed/untrusted code shares that network namespace.
