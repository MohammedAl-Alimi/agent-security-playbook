# Checklist — Pre-Deploy

The final gate before production.

## Automated gates (all must be green)
- [ ] Security regression suite passes: 401/403 table, RLS tests, webhook signature/replay tests ([15](../rules/15-testing-verification.md))
- [ ] Secret scan clean (gitleaks/TruffleHog) over the full history being pushed ([05](../rules/05-secrets-and-env.md))
- [ ] SAST clean or triaged (Semgrep/CodeQL) ([14](../rules/14-supply-chain.md))
- [ ] Dependency audit run; known-critical vulns resolved or documented ([14](../rules/14-supply-chain.md))
- [ ] RLS linter (e.g. splinter) reports no tables without RLS ([04](../rules/04-database-rls.md))

## Manual sweeps
- [ ] Canary sweep: no real customer data in the repo (fixtures/seeds/notebooks), staging DB, CI logs, or client bundle; error-tracker `sendDefaultPii` off ([17](../rules/17-client-data-protection.md))
- [ ] Grep for landmines: `dangerouslySetInnerHTML`, `USING (true)`, `Access-Control-Allow-Origin: *`, `Math.random()` near tokens, `service_role` outside server-only modules
- [ ] Prod env vars set for **all** validated keys — a missing one must fail boot, verify it does ([05](../rules/05-secrets-and-env.md))
- [ ] Security headers live: CSP, HSTS, frame-ancestors, nosniff — check the actual deployed response ([10](../rules/10-headers-csp-cors.md))
- [ ] Cookies: httpOnly, secure, sameSite ([01](../rules/01-authentication.md))
- [ ] Error pages leak nothing: trigger a 500 in prod mode, confirm generic message + request ID only ([09](../rules/09-logging-and-errors.md))
- [ ] Payments: fulfillment only via verified webhook; test-mode keys nowhere near prod ([12](../rules/12-payments.md))
- [ ] Rate limits active on auth, email, LLM, payment routes — verify a burst actually 429s ([07](../rules/07-rate-limiting.md))
- [ ] Caching verified on the deployed URL: authenticated routes never `x-vercel-cache: HIT` and send `no-store`; two-user isolation test green ([16](../rules/16-caching-cdn.md))

## Platform & operations
- [ ] Deployment protection on preview URLs verified (unauthenticated fetch hits the auth interstitial) ([25](../rules/25-deployment-infrastructure.md))
- [ ] Boot assertion confirms prod isn't running test keys or dev project refs ([25](../rules/25-deployment-infrastructure.md))
- [ ] DMARC record present on the sending domain (`dig TXT _dmarc.<domain>`) ([23](../rules/23-email-sms-notifications.md))
- [ ] Security alerts + canary tokens live; incident runbook filled in and reachable ([22](../rules/22-detection-incident-response.md))
- [ ] Debug/preview endpoints and deployment previews protected or disabled
- [ ] Monitoring wired: security events (`authn_login_fail`, `authz_fail`, `rate_limit_exceeded`) visible in logs ([09](../rules/09-logging-and-errors.md))
- [ ] Rollback path known and tested
