# Gap Analysis — 2026-08

## 1. Executive Summary

The playbook's 17 chapters are strong on first-party application mechanics — authn/session cookies, RLS, input validation, secrets, webhooks, payments, logging, dependency consumption, and single-call LLM hygiene — and unusually current on mid-2025 incidents (CVE-2025-29927, Shai-Hulud 1.0, Supabase key migration). The gaps cluster in four bands: **classic web classes the playbook skipped** (output encoding/XSS on ordinary user data, OAuth/federated login, business-logic integrity), **everything downstream and around the app** (detection/IR, deployment/infra, email/DNS, realtime channels), **the agent era it was written for but doesn't cover** (MCP, RAG authorization, agent memory, the coding agent itself), and **post-cutoff events** (React2Shell, Dec 2025). Six of seven researchers independently converged on federated login, XSS sinks, and workflow integrity, making those the highest-confidence structural holes.

**Top 10 gaps** (ranked by priority, then breadth of evidence):

1. **Output encoding & DOM XSS sink discipline** — no rules govern `dangerouslySetInnerHTML`/`innerHTML`/URL schemes on ordinary user data; flagged independently by 3 dimensions (ASVS-delta, realtime-clientside, email HTML injection).
2. **OAuth/federated login** — PKCE/state, exact redirect URIs, open redirects, and the nOAuth-class account-linking takeover (Better Auth CVE-2026-53516); flagged by 2 dimensions, zero current coverage.
3. **Business-logic & workflow integrity** — no server-side state machines, step-order enforcement, or one-shot semantics outside payments; flagged by 2 dimensions (ASVS V2/V11, WSTG ch10).
4. **MCP security** — tool poisoning, confused deputy, token passthrough, and the first in-the-wild malicious MCP server (postmark-mcp); flagged by 2 dimensions; "MCP" appears nowhere in the rules.
5. **Agent containment** — lethal trifecta, memory poisoning, and hardening the coding agent that builds the app (s1ngularity/Nx); flagged by 2 dimensions.
6. **React2Shell (CVE-2025-55182 / CVE-2025-66478)** — CVSS 10.0 unauthenticated RCE in the playbook's exact target stack, exploited in the wild, unmentioned.
7. **Detection & incident response** — the playbook produces telemetry (ch09) but has no alerting thresholds, canaries, tested backups, runbook, or GDPR 72-hour workflow; the entire dimension is open.
8. **Email/messaging security** — SPF/DKIM/DMARC, header/HTML injection, email-change account takeover, and scanner-safe magic/reset links; magic-link failures corroborated by 2 dimensions.
9. **Realtime channel security** — CSWSH on WebSockets, Supabase Realtime channels public by default (table RLS does not cover Broadcast/Presence), SSE auth model.
10. **Deployment & infrastructure hardening** — container security, subdomain takeover via dangling Vercel CNAMEs, Vercel Deployment Protection, and per-environment platform instances.

Close behind: RAG retrieval authorization (OWASP LLM08), browser script supply chain (polyfill.io/SRI), free-trial multi-accounting, and feature-flag/admin exposure — all high priority, all in the roadmap below.

---

## 2. Proposed Roadmap

### New chapters (priority order)

**Chapter 18 — Output Encoding & XSS** (P0; merges ASVS-delta V1 + realtime-clientside DOM-sink gaps)
- Ban `dangerouslySetInnerHTML`/`v-html`/`innerHTML`/`insertAdjacentHTML` on any user- or third-party-derived value (not just LLM output); grep-verify zero unsanctioned hits.
- All legitimate rich HTML flows through one sanctioned sanitizer module (DOMPurify with documented allowlist, or rehype-sanitize) applied at the render site — never write-time-only, never ad-hoc regex.
- User-supplied URLs in `href`/`src` pass a scheme allowlist (https/mailto); reject `javascript:`/`data:` — CSP does not block `javascript:` in all sinks.
- Render LLM/markdown output via a markdown renderer with HTML disabled (cross-link ch13); entity-escape JSON embedded in `<script>` tags.
- Adopt Trusted Types (`require-trusted-types-for 'script'`) where supported; feature-detect the native Sanitizer API (`setHTML()`, limited availability) with DOMPurify fallback.
- Semgrep/lint rule flagging every innerHTML-family and eval-family sink in CI (extends ch14/ch15); E2E test storing an XSS payload in every user-writable field.

**Chapter 19 — Business Logic & Workflow Integrity** (P0; merges ASVS-delta V2 + business-logic dimension)
- Every multi-step flow is an explicit server-side state machine: status enum + allowed-transition table, checked and advanced in one transaction (`UPDATE ... WHERE status='paid'`, verify rowcount); status fields never client-settable (extends ch03).
- Derived values (totals, scores, discounts, pass/fail) always recomputed server-side; client copies rejected.
- One-shot semantics (trials, coupons, invites, votes) enforced with DB UNIQUE constraints, never check-then-insert; generalize ch12's parallel-request race test to every consume-once endpoint.
- Coupons/referrals: no stacking by default, no discounts on stored-value products, Stripe-native limits (`max_redemptions`, `first_time_transaction`), referral payout only after first paid invoice with self-referral denial and clawback.
- Trial abuse: enable Clerk disposable-email + subaddress blocking; normalize emails before entitlement checks; meter costly features (LLM credits) per verified identity, not per account.
- Inventory holds carry `expires_at` with automatic release, per-identity hold caps, atomic hold→sale conversion on payment webhook.
- Feature flags are rollout tools, never authorization: flag-gated handlers still run server-side authz; never ship the full flag ruleset to the client (extends ch02).

**Chapter 20 — OAuth, Federated Login & Account Lifecycle** (P0; merges ASVS-delta V10 + oauth-sso dimension + magic-link halves of email-messaging)
- Authorization Code + PKCE only (RFC 9700); CSPRNG `state` bound to session; verify id_token iss/aud/nonce/exp server-side; exact-match registered redirect URIs, no wildcards.
- Account linking: identify users by immutable `sub`, never email; auto-link only when both sides assert verified email, else require fresh re-auth (nOAuth/Better Auth CVE-2026-53516 defense); self-verification test that pre-registered unverified email + OAuth login do NOT merge.
- Open redirects: any `returnTo`/`next`/`redirect_url` param validated as same-origin relative path against an allowlist; grep-verify `redirect(req.query...)`; callback pages free of third-party assets, strip code/state from URLs immediately.
- Magic links: 32+ byte CSPRNG token stored hashed, ≤15 min expiry, consumed atomically via POST from a confirmation page — never on GET (defeats Defender/Mimecast prefetch); OTP fallback for enterprise recipients.
- Session lifecycle (extends ch01): regenerate session ID on every privilege transition; revoke all other sessions on password change/reset; absolute + idle timeouts; pre/post-login cookie test in ch15.
- Passkeys: use Clerk/Supabase implementations; pin RP ID explicitly (never Host header); recovery paths get the same rigor as the passkey itself.
- SAML: never hand-roll (ruby-saml parser-differential class, CVE-2025-25291/66567); delegate to Clerk Enterprise SSO/WorkOS; per-tenant IdP scoping.
- Provider tokens: AES-GCM storage (ch06), minimum scopes, revoke at provider on disconnect (ties to ch17 DSR).

**Chapter 21 — Agent, MCP & RAG Security** (P0; merges agent-mcp-rag dimension + emerging-2026 MCP/agent gaps; heavy ch13 cross-links)
- Lethal trifecta rule: no agent context combines private-data reads + untrusted-content ingestion + external egress; downgrade tools after untrusted ingestion; dual-LLM or plan-then-execute patterns; CI manifest test asserting no agent definition holds all three legs — applied to both in-app agents and the dev-time coding agent.
- Shipping MCP servers: OAuth 2.1 resource-server model (RFC 9728 metadata, RFC 8707 resource-bound tokens), token passthrough forbidden, per-client consent for proxied third-party flows, CSPRNG session IDs bound to user ID.
- Consuming MCP servers: install only from vendor-verified registry entries, pin versions with release-age cooldown, hash tool descriptions at approval and re-approve on change (rug-pull defense), one scoped credential per server, never combine attacker-readable-content servers with private-data + write/egress servers (GitHub MCP toxic-flow pattern).
- RAG: retrieval runs AS the requesting user — pgvector under RLS (Supabase rag-with-permissions pattern), tenant namespaces + metadata ACL filters for external stores, permission revocation propagates to the index, embeddings treated as sensitive as source text, retrieved chunks are untrusted data.
- Agent memory: schema-validate and provenance-tag all memory writes, partition per user/role (cross-user memory read = IDOR), memory re-enters context as untrusted; sub-agent output is untrusted input to orchestrators; poisoned-memory fixture test.
- Dev-agent hardening: never run coding agents with `--dangerously-skip-permissions`/`--yolo` on untrusted repos or CI; scoped short-lived credentials in the agent shell env; sandbox dependency installs (s1ngularity lesson).
- Operational caps: AI Gateway per-key enforced budgets (noting BYOK bypass), `stopWhen` loop ceilings, AI SDK 6 `needsApproval` over hand-rolled approval queues.

**Chapter 22 — Detection, Alerting & Incident Response** (P0; detection-ir dimension)
- Page-worthy alert list keyed to ch09's event vocabulary (login-fail spikes, authz-fail bursts, service-role use from unexpected origins, mass-export signals), wired via Vercel Drains/Sentry alerts; every alert is "page now" or "digest daily"; dead-man test that a synthetic burst fires the alert.
- Canary tokens: fake AWS key in prod env vars, canary rows in the user table, canary URL in LLM system prompts; each token mapped in the runbook to "what's compromised, what to rotate"; fire one quarterly.
- Backups as recovery control (extends ch04): know the Supabase tier (daily vs PITR); offsite `pg_dump` to a different provider/account with independent read-only credentials (Code Spaces rule); quarterly restore test into a scratch project; document crypto-shred/restore-point interaction.
- One-page NIST 800-61r3-aligned runbook in `templates/`: severity ladder, first-hour checklists per scenario, kill-switch inventory with exact CLI/dashboard paths, contacts.
- GDPR Art. 33/34 (extends ch17): 72h clock starts at awareness; notify-authority decision rule; mandatory internal breach register even for non-notified breaches; pre-filled authority URL and draft skeleton.
- Status page on independent infrastructure (Upptime/Instatus) with pre-drafted investigating/identified/resolved templates.

**Chapter 23 — Email, SMS & Notifications** (P1; email-messaging dimension minus link-handling merged into ch20)
- Dedicated sending subdomain in Resend; DMARC `p=none`→`quarantine`→`reject` with reporting; DKIM strict alignment noted; `dig TXT _dmarc` pre-launch check; separate marketing/transactional streams.
- Email injection: reject `\r\n` in any header-bound field (Zod refinement); SDK structured fields only; HTML-escape every interpolated value in bodies; recipient lists from DB, never request bodies; Semgrep rule on template-literal `html:` near `resend.emails.send`.
- Email/phone change = account takeover surface: fresh re-auth required, switch only after NEW address confirms, notify OLD address with revert link, Supabase `double_confirm_changes` ON with `mailer_autoconfirm` false verified end-to-end, invalidate old-address reset tokens.
- SMS/OTP: 3–5 verify attempts then invalidate, constant-time compare; per-phone cooldowns + destination-country allowlist + line-type lookup (SMS-pumping defense); SMS is a NIST-restricted factor — never sole authorization for email/password changes.
- RFC 8058 one-click unsubscribe: per-recipient HMAC token (never raw ID/email), POST-only consumption, GET renders confirmation, list-scoped tokens, security notifications never suppressible.

**Chapter 24 — Realtime & Client-Side Channels** (P1; realtime-clientside dimension)
- WebSockets: wss:// only; authenticate the upgrade itself; exact-match Origin allowlist (browsers don't enforce same-origin for WS — CSWSH); per-connection token beyond cookies; per-message re-authorization and Zod validation; no tokens in WS URLs; connection/message rate caps (extends ch07).
- Supabase Realtime (also extends ch04): Broadcast/Presence are public by default and table RLS does NOT cover them — `private: true` on every channel, RLS on `realtime.messages` scoping topics to tenant, disable "Allow public access", `setAuth()` after token refresh, cross-tenant subscription test in ch15.
- SSE: auth per-handler like any route; short-lived single-use stream tickets, never long-lived tokens in query strings; validate Origin/Sec-Fetch-Site; streamed LLM chunks never accumulated into innerHTML; idle timeouts + concurrent-stream caps.
- postMessage: exact-match origin checks (substring/regex checks are findings), no `*` targetOrigin with sensitive data, Zod-validate `event.data`, prefer MessageChannel for widgets.
- Embedding: `sandbox` + minimal `allow=` on any third-party/user-influenced iframe; never `allow-same-origin`+`allow-scripts` on same-site user content; gesture-gating for sensitive one-click confirmations (DoubleClickjacking bypasses frame-ancestors entirely).

**Chapter 25 — Deployment & Infrastructure** (P1; infra-deploy dimension + ASVS V13 config gaps)
- Containers: multi-stage builds, digest-pinned slim/distroless base, non-root USER + no-new-privileges, no secrets in ARG/ENV/layers, `.dockerignore` for `.env*`; CI gates: hadolint, Trivy image scan (fail HIGH/CRITICAL), Checkov/`trivy config`.
- DNS hygiene: remove DNS records BEFORE deleting Vercel projects; DNS inventory in-repo; periodic CNAME audit against can-i-take-over-xyz; host-only cookies so a lost subdomain can't read sessions (cross-link ch01).
- Vercel Deployment Protection: Standard Protection on every project (previews + `*.vercel.app` URLs require SSO); verify git-branch aliases covered on older projects; bypass secrets treated per ch05; ch15 test that unauthenticated preview fetch hits the auth interstitial.
- Environment separation: Clerk production instance (`pk_live_`), Supabase project per environment, boot-time assertion failing prod startup on `_test_` keys or dev project refs; migrations flow dev→staging→prod via CI; anonymized data only in staging.
- Prod config hardening (extends ch05, rename "Secrets, Env & Configuration"): FastAPI `docs_url`/`openapi_url` None or gated in prod; debug=False asserted at boot; no seed/debug routes in prod builds; source maps not public; pre-deploy curl check for `/docs`, `/openapi.json`, source maps → 401/404.
- TLS for self-hosted FastAPI: reverse proxy with Mozilla intermediate profile, TLS 1.2+ AEAD only, ACME auto-renew, testssl.sh in ch15.
- `/.well-known/security.txt` (RFC 9116) templated in `templates/` with Contact, Expires, and a one-paragraph disclosure policy.

### Extensions to existing chapters (priority order)

**ch01 + ch15 — React2Shell (P0, do first — smallest diff, highest severity):** raise the CI lockfile gate to fail on react/react-dom/react-server-dom-* < 19.0.1/19.1.2/19.2.1 and unpatched Next.js (CVE-2025-66478); standing rule that framework patch releases are same-week deploys verified by a recurring CI job; threat-model line that RSC flight payloads are attacker-controlled serialized input; Vercel WAF rules are stopgap-only.

**ch14 — Supply chain, both directions (P1):**
- MCP servers are dependencies with credentials (see ch21 rules; consumption hygiene lands here).
- Publishing side: npm trusted publishing (OIDC) with no stored tokens; granular short-lived tokens where unavoidable; FIDO-only 2FA; prefer/verify provenance attestations; note Shai-Hulud 2.0 (Nov 2025) proves recurrence.
- SBOM: CycloneDX via Syft/Trivy on every release, attached to release artifacts; scan stored SBOMs on advisory days; CRA timeline (reporting Sept 2026) as compliance driver.
- Browser-loaded scripts: self-host/bundle by default (polyfill.io case study); SRI `integrity` + `crossorigin` on any cross-origin script, exact versions only; GTM containers treated as production code, never on payment pages (PCI DSS 4.0 §6.4.3); CI grep for external `<script src>` without integrity.
- Dangerous-sink Semgrep pack (with ch03): ban pickle/`yaml.load`/eval/`Function()` on external data; no hand-rolled recursive merges (prototype pollution — strip `__proto__`/`constructor`/`prototype` at the Zod/Pydantic boundary, `--disable-proto=delete`); `execFile`/`spawn` array-args only, `shell=False`; no `Template(user_string)` (SSTI).

**ch07 + ch03 — Resource caps beyond rate limiting (P1):** body-size caps before parsing; schema-bounded pagination (`max(100)`); ReDoS hygiene (Zod built-ins over hand-written regex, ReDoS linter in CI); LLM endpoints get input-token caps, `maxOutputTokens`, tool-call iteration ceilings, per-user daily spend budgets; tests for oversized body → 413 and budget breach → 429.

**ch12 — Order math (P1):** quantity = `z.number().int().positive().max(CAP)`; recompute all derived numbers server-side; currency fixed per Stripe price ID; Postgres `CHECK (quantity > 0)` mirrors (ch04); test quantity ∈ {-1, 0, 0.5, 2³¹} + tampered totals.

**ch04 — Soft delete (P2):** every RLS policy/view filters `deleted_at IS NULL`; deleting a user revokes sessions/tokens in the same operation; partial unique indexes (`WHERE deleted_at IS NULL`); secrets are hard-deleted or crypto-shredded, never soft-deleted; restore is a privileged audited transition.

**ch06 — Supabase asymmetric JWT keys (P2):** RS256/ES256 default since Oct 2025; FastAPI verifies against the project JWKS with an alg allowlist, never a copied shared secret; standby-key rotation flow.

**PLAYBOOK.md — OWASP Top 10:2025 remap (P3):** one-line cross-reference table — ch14 → A03 Software Supply Chain Failures, ch07/ch09 fail-closed → A10 Mishandling of Exceptional Conditions, SSRF (ch13) → Broken Access Control.

---

## 3. Per-Dimension Detail

### 3.1 asvs-delta

**Verdict:** ~12 of ASVS 5.0's 17 chapters covered well; structural blind spots in V1 Encoding/Sanitization, V2 business logic, V10 OAuth/OIDC, V13 configuration, and V15 dangerous sinks.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| Output encoding/XSS as first-class chapter (V1) — no rules for `dangerouslySetInnerHTML` on ordinary user data, `javascript:` hrefs, DOM sinks, or a sanctioned sanitizer; ch13's grep scopes to LLM values only | High | **New ch18** (merged with realtime-clientside DOM-sink gap) | https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md · https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html · https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html |
| Business logic/workflow verification (V2) — no server-side state machines, step order, or TOCTOU outside payments | High | **New ch19** (merged with business-logic dimension) | https://github.com/OWASP/ASVS/blob/master/5.0/en/0x11-V2-Validation-and-Business-Logic.md · https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html |
| OAuth/OIDC + open redirects (V10) — ch06 only covers token storage; state/PKCE, exact redirect URIs, `returnTo` validation all absent | Medium | **New ch20** (merged with oauth-sso dimension) | https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md · https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html · https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html |
| Dangerous sinks (V15): pickle/yaml.load, prototype pollution, command injection, SSTI — validated strings still reach unbanned sinks | Medium | **Extend ch03/ch14** (Semgrep pack) | https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md · https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html · https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html · https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html · https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html |
| Config hardening (V13): public FastAPI `/docs`/`/openapi.json`, debug flags, seed routes, source maps, unprotected previews | Medium | **Extend ch05 / new ch25** | https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md · https://fastapi.tiangolo.com/tutorial/metadata/ · https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html |
| Resource exhaustion beyond rate limiting: ReDoS, unbounded bodies, pagination, LLM cost-DoS | Medium | **Extend ch07/ch03** | https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html · https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md |

### 3.2 oauth-sso

**Verdict:** First-party session/credential hygiene is solid; federated login is a near-total blind spot — zero mentions of oauth/pkce/redirect_uri/saml/magic-link/session-fixation in rules/ or checklists/.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| OAuth/OIDC flow hardening (state+PKCE, exact redirect match, code-only, Referer leakage, `next` param) — next-auth CVE-2022-24858 precedent | High | **New ch20** | https://www.rfc-editor.org/info/rfc9700/ · https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html · https://advisories.gitlab.com/pkg/npm/next-auth/CVE-2022-24858 · https://supabase.com/docs/guides/auth/redirect-urls |
| Account-linking pre-ATO (nOAuth class): Better Auth CVE-2026-53516, Authorizer CVE-2026-35511 — auto-link by email merges attacker's unverified row | High | **New ch20** | https://github.com/advisories/GHSA-g38m-r43w-p2q7 · https://advisories.gitlab.com/golang/github.com/authorizerdev/authorizer/CVE-2026-35511/ · https://github.com/better-auth/better-auth/pull/9578 |
| Magic-link security: hashed CSPRNG tokens, POST-consumption vs mail-scanner prefetch, rate limiting | High | **New ch20** (merged with email-messaging transactional-link gap) | https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html · https://securityboulevard.com/2026/05/are-magic-links-secure-a-technical-deep-dive-into-email-based-authentication/ · https://supabase.com/docs/guides/auth/redirect-urls |
| Session rotation on privilege change (fixation); revoke-all on password reset | Medium | **Extend ch01** (via ch20 work item) | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |
| Passkeys: RP ID pinning, phishable fallback/recovery parity | Medium | **New ch20** | https://learn.microsoft.com/en-us/aspnet/core/security/authentication/passkeys/?view=aspnetcore-10.0 · https://www.corbado.com/blog/passkey-fallback-recovery · https://techcommunity.microsoft.com/blog/microsoft-entra-blog/passkeys-aren%E2%80%99t-the-finish-line-eliminating-fallbacks-and-fixing-recovery/3627345 |
| SAML parser-differential class (CVE-2025-25291/25292, CVE-2025-66567): never hand-roll, per-tenant IdP scoping | Low | **New ch20** | https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/ · https://rubysec.com/advisories/CVE-2025-25291/ · https://portswigger.net/research/the-fragile-lock · https://securityonline.info/critical-authentication-bypass-flaws-discovered-in-ruby-saml-library-cve-2025-66567-cve-2025-66568/ |

### 3.3 infra-deploy

**Verdict:** Strong application-layer controls, essentially no infrastructure/deployment chapter — containers, DNS, Vercel protection, environment separation, TLS, SBOM, and disclosure are absent bar one unactionable checklist line.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| Container hardening (non-root, distroless, no secrets in layers, hadolint/Trivy/Checkov CI gates) | High | **New ch25** | https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html · https://github.com/aquasecurity/trivy · https://github.com/hadolint/hadolint · https://github.com/bridgecrewio/checkov |
| Subdomain takeover via dangling Vercel CNAMEs — DNS-first decommission order, inventory, host-only cookies | High | **New ch25** | https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html · https://github.com/EdOverflow/can-i-take-over-xyz · https://github.com/EdOverflow/can-i-take-over-xyz/issues/183 |
| Vercel Deployment Protection for previews and `*.vercel.app` URLs; separate preview env vars | High | **New ch25** | https://vercel.com/docs/deployment-protection · https://vercel.com/docs/deployment-protection/methods-to-protect-deployments · https://vercel.com/changelog/more-secure-deployment-protection |
| Environment separation: Clerk prod instance, Supabase project per env, boot-time `_test_`-key assertion | Medium | **New ch25 / extend ch05** | https://clerk.com/docs/guides/development/deployment/production · https://clerk.com/blog/how-to-take-your-clerk-app-to-prod · https://supabase.com/blog/the-vibe-coders-guide-to-supabase-environments |
| SBOM generation/publication (CycloneDX via Syft/Trivy; CRA timeline) | Medium | **Extend ch14** | https://github.com/anchore/syft · https://github.com/aquasecurity/trivy · https://appsecsanta.com/sca-tools/sbom-tools-comparison |
| security.txt / disclosure policy (RFC 9116) | Low | **New ch25 + templates/** | https://www.rfc-editor.org/info/rfc9116/ |
| TLS baseline for self-hosted FastAPI (Mozilla intermediate, testssl.sh verify) | Low | **New ch25** | https://ssl-config.mozilla.org/ · https://github.com/testssl/testssl.sh |

### 3.4 realtime-clientside

**Verdict:** Strong server-side HTTP surface; essentially no coverage of realtime channels or deep client-side risk — a real hole given the stack's Supabase Realtime and LLM streaming.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| WebSocket security: auth on upgrade, Origin allowlist, per-message authz (CSWSH) | High | **New ch24** | https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html · https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking · https://vercel.com/kb/guide/do-vercel-serverless-functions-support-websocket-connections |
| Supabase Realtime channels public by default; table RLS does not cover Broadcast/Presence; `private: true` + `realtime.messages` policies required | High | **New ch24 + extend ch04** | https://supabase.com/docs/guides/realtime/authorization · https://supabase.com/blog/supabase-realtime-broadcast-and-presence-authorization |
| SSE auth model: EventSource can't send headers → tokens land in query strings or endpoints go unauthenticated; streamed LLM chunks into innerHTML | Medium | **New ch24** | https://html.spec.whatwg.org/multipage/server-sent-events.html · https://vercel.com/i/websocket-vs-server-sent-events · https://vercel.com/kb/guide/do-vercel-serverless-functions-support-websocket-connections |
| Browser script supply chain: SRI + self-hosting (polyfill.io), tag-manager governance, PCI 6.4.3 | High | **Extend ch14** | https://sansec.io/research/polyfill-supply-chain-attack · https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity · https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html · https://blog.clientsideintel.com/google-tag-manager-pci-dss-4.html |
| DOM XSS sink discipline: DOMPurify at render site, Trusted Types, Sanitizer API status | High | **New ch18** (merged with asvs-delta V1 gap) | https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API · https://wicg.github.io/sanitizer-api/ · https://alfy.blog/2026/05/07/html-sanitizer-api.html |
| postMessage: exact-origin checks, no `*` targetOrigin, MessageChannel for widgets | Medium | **New ch24** | https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised · https://knowledge-base.secureflag.com/vulnerabilities/broken_authorization/unchecked_origin_in_postmessage_vulnerability.html |
| iframe sandbox/allow attributes; DoubleClickjacking bypasses frame-ancestors — gesture-gate sensitive confirmations | Medium | **New ch24 + extend ch10** | https://www.evil.blog/2024/12/doubleclickjacking-what.html · https://www.bleepingcomputer.com/news/security/new-doubleclickjacking-attack-exploits-double-clicks-to-hijack-accounts/ · https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html |

### 3.5 email-messaging

**Verdict:** Essentially uncovered — Resend appears only as an env-var example, webhook source, and one rate-limit line; no domain authentication, injection, email-change, link-handling, OTP, or unsubscribe guidance.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| SPF/DKIM/DMARC with enforcing policy; Gmail/Yahoo hard requirements; sending subdomain | High | **New ch23** | https://resend.com/docs/dashboard/domains/dmarc · https://resend.com/blog/email-authentication-a-developers-guide · https://support.google.com/a/answer/81126 |
| Email injection: CRLF headers (nodemailer GHSA-268h-hp4c-crq3) + unescaped HTML bodies (Papra GHSA-6f8x-2rc9-vgh4) | High | **New ch23** | https://github.com/nodemailer/nodemailer/security/advisories/GHSA-268h-hp4c-crq3 · https://github.com/OWASP/www-project-web-security-testing-guide/blob/master/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection.md · https://github.com/papra-hq/papra/security/advisories/GHSA-6f8x-2rc9-vgh4 · https://semgrep.dev/blog/2020/how-to-prevent-html-email-injection-in-python-web-apps/ |
| Email/phone-change ATO: verify-new + notify-old + re-auth; Supabase `mailer_autoconfirm` silent bypass (supabase/auth #2600) | High | **New ch23** (cross-link ch01) | https://supabase.com/docs/guides/auth/general-configuration · https://github.com/supabase/auth/issues/2600 · https://gitlab.com/gitlab-org/gitlab/-/issues/339145 · https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html |
| Transactional links consumed by scanners; atomic single-use POST consumption; no tokens/PII in emailed URLs | High | **Merged into ch20** magic-link rules | https://github.com/orgs/supabase/discussions/41618 · https://github.com/better-auth/better-auth/discussions/6985 · https://github.com/better-auth/better-auth/pull/9572 · https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html |
| SMS/OTP: verify-attempt throttling, SIM-swap (NIST restricted factor), SMS-pumping fraud | Medium | **New ch23** (cross-link ch07) | https://pages.nist.gov/800-63-3/sp800-63b.html · https://www.twilio.com/docs/verify/preventing-toll-fraud · https://support.twilio.com/hc/en-us/articles/8360406023067-SMS-Traffic-Pumping-Fraud |
| RFC 8058 one-click unsubscribe without mass-unsubscribe abuse | Medium | **New ch23** | https://datatracker.ietf.org/doc/html/rfc8058 · https://support.google.com/a/answer/81126 · https://www.mailgun.com/blog/deliverability/what-is-rfc-8058/ |

### 3.6 business-logic

**Verdict:** Mechanics exist (race-safe counters ch04, server-side prices ch12, rate limits ch07) but no chapter on workflow integrity, promo/trial abuse, feature-flag exposure, inventory holds, or soft-delete semantics.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| Workflow state-machine bypass (CWE-841, WSTG-BUSL-06, ASVS V11.1.1) | High | **New ch19** (merged with asvs-delta V2 gap) | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows · https://cwe.mitre.org/data/definitions/841.html · https://github.com/OWASP/ASVS/blob/master/4.0/en/0x19-V11-BusLogic.md |
| Coupon/promo/referral abuse: stacking, redeem-once via UNIQUE, self-referral, clawback | High | **New ch19** (cross-link ch12) | https://portswigger.net/web-security/logic-flaws/examples · https://docs.stripe.com/api/promotion_codes/create · https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README |
| Trial multi-accounting / disposable emails (OAT-019, API6:2023); Clerk one-toggle mitigations never enabled | High | **New ch19** | https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-019_Account_Creation · https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/ · https://clerk.com/docs/guides/secure/restricting-access · https://github.com/disposable-email-domains/disposable-email-domains |
| Feature flags/admin panels: hidden is not protected; server-side evaluation; fail-closed kill switches | High | **New ch19 + extend ch02** | https://launchdarkly.com/blog/keeping-client-side-feature-flags-secure/ · https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README · https://docs.launchdarkly.com/sdk/concepts/flag-evaluation-rules |
| Quantity/parameter manipulation: negative/fractional/overflow quantities, client currency (CWE-840) | Medium | **Extend ch12** | https://portswigger.net/web-security/logic-flaws/examples · https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README · https://cwe.mitre.org/data/definitions/840.html |
| Inventory/booking hold abuse (OAT-021 Denial of Inventory, OAT-005 Scalping) | Medium | **New ch19** | https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-021_Denial_of_Inventory · https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-005_Scalping · https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/ |
| Soft-delete semantics: RLS filtering, session revocation, partial unique indexes, secrets never soft-deleted | Medium | **Extend ch04** | https://nhimg.org/glossary/soft-deletion/ · https://dev.to/akarshan/the-delete-button-dilemma-when-to-soft-delete-vs-hard-delete-3a0i · https://learn.microsoft.com/en-us/entra/backup/soft-deletion |

### 3.7 agent-mcp-rag

**Verdict:** ch13 covers single-LLM-call hygiene well but nothing on MCP protocol security, RAG retrieval authorization, agent memory, multi-agent trust, or injection-containment architecture — where 2025-26 standards and incidents concentrated.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| MCP server/client security: tool poisoning, confused deputy, token passthrough, GitHub MCP toxic flow | High | **New ch21** (merged with emerging-2026 MCP supply-chain gap) | https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices · https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization · https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks · https://invariantlabs.ai/blog/mcp-github-vulnerability |
| RAG retrieval authorization (OWASP LLM08:2025): pgvector under RLS, tenant namespaces, revocation propagation, embedding inversion | High | **New ch21** (cross-link ch04) | https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/ · https://supabase.com/docs/guides/ai/rag-with-permissions |
| Lethal trifecta / provable injection-containment design patterns (plan-then-execute, dual-LLM) | High | **New ch21 + extend ch13** (merged with emerging-2026 dev-agent gap) | https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ · https://arxiv.org/abs/2506.08837 · https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/ |
| Agent memory poisoning + multi-agent trust (OWASP Agentic T1/T12/T13) | Medium | **New ch21** | https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/ · https://www.humansecurity.com/learn/blog/agentic-ai-security-owasp-threats/ |
| Operational controls: AI Gateway enforced budgets (BYOK caveat), `stopWhen` loop caps, AI SDK 6 `needsApproval` | Medium | **Extend ch13** | https://vercel.com/docs/ai-gateway/observability-and-spend/budgets · https://vercel.com/changelog/budgets-for-api-keys-on-ai-gateway · https://vercel.com/blog/ai-sdk-6 · https://ai-sdk.dev/cookbook/next/human-in-the-loop |

### 3.8 detection-ir

**Verdict:** ch09 thoroughly covers producing telemetry, but nothing exists downstream of it — no alerting, honeytokens, backup/restore strategy, runbook, breach notification, or incident comms. Almost entirely open.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| Actionable alerting on ch09's event vocabulary (OWASP A09: logs nobody reads) | High | **New ch22** | https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/ · https://vercel.com/docs/alerts · https://vercel.com/docs/drains · https://docs.sentry.io/product/alerts-notifications/ |
| Honeytokens/canaries in env vars, DB rows, LLM prompts | High | **New ch22** | https://docs.canarytokens.org/ · https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html · https://blog.thinkst.com/2025/09/introducing-the-aws-infrastructure-canarytoken.html |
| Backups vs ransomware/deletion: offsite independent-credential copies, tested restores, Supabase PITR (Code Spaces lesson) | High | **New ch22 / extend ch04** | https://supabase.com/docs/guides/platform/backups · https://supabase.com/docs/guides/platform/manage-your-usage/point-in-time-recovery · https://www.breaches.cloud/incidents/codespaces/ · https://www.helpnetsecurity.com/2014/06/19/code-hosting-code-spaces-destroyed-by-extortion-hack-attack/ |
| One-page incident runbook (NIST 800-61r3-aligned) in templates/ | High | **New ch22 + templates/** | https://github.com/counteractive/incident-response-plan-template · https://github.com/magoo/Incident-Response-Plan · https://github.com/securitytemplates/sectemplates/blob/main/incident-response/v1/Incident_response_runbook.md · https://response.pagerduty.com/ · https://csrc.nist.gov/pubs/sp/800/61/r3/ipd |
| GDPR Art. 33/34 72-hour breach workflow + mandatory breach register | Medium | **Extend ch17** (via ch22 runbook) | https://gdpr-info.eu/art-33-gdpr/ · https://www.legiscope.com/blog/gdpr-article-33-breach-notification-authority.html |
| Status page on independent infra + pre-drafted comms | Low | **New ch22** | https://github.com/upptime/upptime · https://instatus.com/blog/best-open-source-status-page-services · https://response.pagerduty.com/ |

### 3.9 emerging-2026

**Verdict:** Unusually current for mid-2025 material, but predates the December 2025 React2Shell RSC RCE and has zero coverage of MCP-server trust or hardening the coding-agent environment.

| Gap | Priority | Disposition | Evidence |
|---|---|---|---|
| React2Shell CVE-2025-55182 (CVSS 10.0) + Next.js CVE-2025-66478: default create-next-app build vulnerable, exploited in the wild within days | High | **Extend ch01/ch15** (do first) | https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components · https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182 · https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/ · https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/ |
| MCP supply chain: postmark-mcp backdoor (first confirmed malicious MCP server), typosquatting, credential scoping | High | **Merged into ch21 + ch14 extension** | https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package · https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/ · https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft · https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html |
| Securing the coding-agent environment (s1ngularity/Nx: AI CLIs weaponized via permission-bypass flags; 5,500+ private repos leaked) | High | **Merged into ch21** dev-agent rules | https://www.wiz.io/blog/s1ngularity-supply-chain-attack · https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ |
| npm publishing hardening post-Shai-Hulud: trusted publishing (OIDC), FIDO-only 2FA, provenance; Shai-Hulud 2.0 recurrence | Medium | **Extend ch14** | https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/ · https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem · https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/ · https://philna.sh/blog/2026/01/28/trusted-publishing-npm/ |
| OWASP Top 10:2025 category remap (citation freshness, not a control gap) | Low | **PLAYBOOK.md cross-reference table** | https://owasp.org/Top10/2025/ · https://owasp.org/Top10/2025/0x00_2025-Introduction/ |
| Supabase asymmetric JWT signing keys (default since Oct 2025): JWKS verification, standby-key rotation | Low | **Extend ch06** | https://supabase.com/blog/jwt-signing-keys · https://supabase.com/docs/guides/auth/signing-keys |

---

**Merge log:** XSS/DOM sinks (asvs-delta + realtime-clientside → ch18) · workflow integrity (asvs-delta + business-logic → ch19) · OAuth flows/redirects (asvs-delta + oauth-sso → ch20) · magic/transactional links (oauth-sso + email-messaging → ch20) · MCP (agent-mcp-rag + emerging-2026 → ch21 + ch14) · lethal trifecta / dev-agent (agent-mcp-rag + emerging-2026 → ch21) · config hardening (asvs-delta V13 + infra-deploy env separation → ch25/ch05). No gaps were dropped: every reported gap carried verified evidence URLs, and all URLs are retained above.
