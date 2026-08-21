# 🧯 Incident Runbook — {{company_name}}

One page, NIST 800-61-aligned. Fill every `{{placeholder}}`, keep a copy OUTSIDE this infrastructure, review quarterly. Last reviewed: {{date}} by {{owner}}.

## Severity ladder

| Sev | Definition | Examples | Response |
|---|---|---|---|
| SEV1 | Active breach or data loss in progress | Service-role key public; user table dumped (canary fired); attacker in prod dashboard; ransomware | Page {{sev1_pager}} now, all hands, GDPR clock check |
| SEV2 | Compromise likely, not confirmed spreading | Leaked secret (unknown use); malicious dependency/MCP server installed; single account takeover | Respond within 1h, incident lead assigned |
| SEV3 | Vulnerability found, no evidence of exploitation | Failing auth test in prod; missing RLS policy discovered; expired security patch | Fix within {{sev3_sla}}, no page |

Undecided between two levels → pick the higher one.

## First hour — by scenario

**Every incident, first 10 minutes:** assign one incident lead ({{default_incident_lead}}) · open an incident doc with a UTC timeline · record the *awareness timestamp* (starts the GDPR clock) · preserve logs before touching anything.

### Leaked secret (key/token/password in repo, logs, or paste site)
- [ ] Identify which secret and its blast radius (what it can read/write)
- [ ] Rotate/revoke via kill-switch table below — revoke FIRST, investigate after
- [ ] Search logs for use of the secret since exposure: {{log_search_path}}
- [ ] Purge from git history / logs / paste source; verify no re-commit
- [ ] If used by an attacker → escalate to data-exposure scenario

### Data exposure (user data read by unauthorized party)
- [ ] Stop the leak: pause project / revoke key / disable endpoint (kill switches below)
- [ ] Scope it: which tables/rows/fields, which users, since when — from audit_log
- [ ] Preserve evidence: export relevant logs to {{evidence_store}}
- [ ] Open the GDPR box below NOW
- [ ] Rotate anything the exposed data unlocks (session tokens, reset links)

### Account takeover (user or admin account controlled by attacker)
- [ ] Revoke ALL sessions for the account: {{session_revoke_path}}
- [ ] Lock the account; if admin → Clerk lockdown (kill switch below)
- [ ] Audit actions taken by the account since compromise (audit_log by actor)
- [ ] Determine vector (phished? credential stuffing? magic-link intercept?) — fix vector before unlock
- [ ] Notify the legitimate owner via known-good channel

### Supply-chain compromise (malicious package, MCP server, or CI action)
- [ ] Freeze deploys: {{deploy_freeze_path}}
- [ ] Identify install window: lockfile diff + `npm ls {{package}}` across environments
- [ ] Assume every secret readable by the build/runtime is burned → rotate ALL (kill-switch table, top to bottom)
- [ ] Check egress logs for exfiltration during the window
- [ ] Pin to known-good version; add to blocklist; postmortem the pin/cooldown gap

## Kill-switch inventory

| Action | Exact path | Owner |
|---|---|---|
| Revoke Supabase service key | {{supabase_dashboard_url}} → Settings → API → rotate `service_role`; CLI: `{{supabase_cli_rotate_cmd}}` | {{owner_db}} |
| Pause Vercel project | {{vercel_dashboard_url}} → Settings → Pause project; CLI: `{{vercel_cli_pause_cmd}}` | {{owner_infra}} |
| Clerk lockdown | {{clerk_dashboard_url}} → {{clerk_lockdown_path}} (disable sign-ins / revoke sessions); API: `{{clerk_revoke_sessions_cmd}}` | {{owner_auth}} |
| Stripe restricted mode | {{stripe_dashboard_url}} → roll API keys to restricted; disable payment links: {{stripe_restrict_path}} | {{owner_payments}} |
| Freeze CI/deploys | {{deploy_freeze_path}} | {{owner_infra}} |
| Rotate offsite-backup creds | {{backup_provider_path}} | {{owner_db}} |

## Contacts

| Role | Name | Channel (primary / backup) |
|---|---|---|
| Incident lead (default) | {{name}} | {{phone}} / {{email}} |
| Infra owner | {{name}} | {{phone}} / {{email}} |
| Legal / DPO | {{name}} | {{phone}} / {{email}} |
| Supabase support | — | {{supabase_support_url}} |
| Vercel support | — | {{vercel_support_url}} |
| Supervisory authority (GDPR) | {{authority_name}} | {{authority_notification_url}} |

## GDPR 72h decision box

- Awareness timestamp (UTC): `____________` → deadline = +72h: `____________`
- Personal data involved? ☐ yes ☐ no — if no, close box, still log in register.
- Risk to individuals' rights unlikely (e.g., encrypted, keys safe)? ☐ yes → no authority notification, register only. ☐ no/unsure → **notify authority before deadline**: {{authority_notification_url}} (draft skeleton: {{breach_draft_path}}). Undecided at hour 48 → notify.
- High risk (credentials, financial, special-category data)? ☐ yes → also notify affected users (Art. 34) via {{user_notification_channel}}.
- ALWAYS: add entry to internal breach register {{breach_register_path}} — what, when aware, scope, decision + reasoning, actions taken.

## Post-incident review (within {{postmortem_sla}} days, blameless)

1. Timeline: first malicious action → detection → containment. Where was the biggest lag, and why?
2. Which control failed or was missing? Which playbook chapter covers it — and was the rule unimplemented or wrong?
3. Did detection come from our alerts/canaries or from outside? If outside, what alert would have caught it?
4. Were the kill switches accurate and fast enough? Fix any stale path in this runbook now.
5. What single change most reduces recurrence risk? File it with an owner and a date.
