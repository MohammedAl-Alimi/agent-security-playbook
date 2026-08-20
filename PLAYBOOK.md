# The Playbook

The threat model and reasoning behind the rules. If [`AGENT-INSTRUCTIONS.md`](AGENT-INSTRUCTIONS.md) is the *what*, this is the *why*.

---

## 1. The threat model: AI code fails by omission

Human-written insecure code tends to contain *mistakes* — a bad regex, a wrong flag. AI-generated insecure code tends to contain *absences*: the model writes a working feature and silently omits the layer that would have made it safe. The RLS policy. The ownership check on the query. The signature verification on the webhook. The rate limiter on the login route. The password hash.

This is well documented (full citations in [`research/`](research/security_and_replication_findings.md)):

- **Veracode (2025)**, testing 100+ LLMs across 80 tasks: vulnerabilities introduced in ~45% of coding tasks; newer models got better at syntax, not security.
- **Pearce et al. (IEEE S&P 2022)**: ~40% of Copilot-generated programs vulnerable.
- **GitGuardian**: AI-assisted commits leak secrets at more than twice the human rate.
- **Stanford (Perry et al.)**: developers with AI assistants wrote less secure code *and rated it as more secure* — vigilance doesn't scale.
- **CVE-2025-48757**: 170+ Lovable-built apps world-readable because tables shipped without RLS.
- **EnrichLead**: paywall bypassed from the browser console within 72 hours of launch — fulfillment trusted a client redirect.

The failure is invisible in the demo. The happy path works. Nobody notices until someone hostile shows up.

## 2. The consequence: structure beats vigilance

If omission is the failure mode, "remember to add auth" is not a defense. The playbook's rules are therefore designed to be **default-on infrastructure**:

- **Build failures**, not conventions — env validation that won't compile with a leaked secret prefix; `import 'server-only'` that breaks the build if a secret module reaches the client.
- **Mandatory wrappers**, not per-route discipline — one authenticated action client, one validated fetch helper, one webhook verifier that every handler goes through.
- **Database-level backstops** — RLS and constraints hold even when the app layer forgets.
- **Negative tests and CI gates** — a security rule that can regress without turning CI red is a suggestion, not a rule.

## 3. Defense in depth: the layer map

Every chapter defends a layer; an attacker has to get through all of them. A missing layer elsewhere should be caught by the next one down:

| Layer | Chapter(s) | Backstop for |
|---|---|---|
| Edge (WAF, bots, limits, cache) | [07](rules/07-rate-limiting.md), [10](rules/10-headers-csp-cors.md), [16](rules/16-caching-cdn.md) | volumetric abuse, injection blast radius, cross-user cache leaks |
| Transport & headers | [10](rules/10-headers-csp-cors.md) | XSS, clickjacking, CSRF |
| Identity | [01](rules/01-authentication.md), [06](rules/06-hashing-and-tokens.md) | stolen creds, forged sessions |
| Authorization | [02](rules/02-authorization.md) | IDOR, privilege escalation |
| Input | [03](rules/03-input-validation.md) | mass assignment, injection |
| Data | [04](rules/04-database-rls.md) | every app-layer omission above |
| Side effects | [08](rules/08-webhooks.md), [11](rules/11-file-uploads.md), [12](rules/12-payments.md), [13](rules/13-ssrf-and-llm.md) | forged events, hostile files, forged URLs |
| Secrets & supply chain | [05](rules/05-secrets-and-env.md), [14](rules/14-supply-chain.md) | leaks, malicious packages |
| Observability | [09](rules/09-logging-and-errors.md) | detection, forensics |
| Verification | [15](rules/15-testing-verification.md) | regression of all of the above |

## 4. Rule design principles

Every rule in [`rules/`](rules/) follows the same contract:

1. **Testable imperative** — phrased so a machine can check compliance.
2. **❌/✅ pair** — the exact wrong pattern an agent is likely to generate, next to the right one, because agents pattern-match on code more reliably than on prose.
3. **Verify line** — the test, grep, or CI gate that catches regression.
4. **Evidence** — grounded in a real CVE, breach, or study where one exists; no rules invented from vibes.

## 5. Scope and honesty

This playbook targets the dominant vibe-coded stack shape — TypeScript/Next.js-style web apps with a Postgres backend, plus Python/FastAPI services — because that's where the documented failures are. The principles (fail closed, parse don't validate, authorize in the data layer, verify then trust) are universal; the code examples are not gospel for every stack.

It is also not a compliance framework. It won't make you SOC 2 or GDPR compliant by itself — it makes the *engineering* layer defensible, which is the part AI agents keep getting wrong.

## 6. Sources

Every statistic, CVE, and incident referenced anywhere in this repo is indexed with its URL in [`research/security_and_replication_findings.md`](research/security_and_replication_findings.md) — a 16-agent, web-verified research pass over OWASP projects, framework docs, breach postmortems, and the leading boilerplates' actual source code.
