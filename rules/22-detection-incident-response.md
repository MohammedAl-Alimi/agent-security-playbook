# 🚨 Detection & Incident Response

Chapter [09](09-logging-and-errors.md) makes your app produce telemetry; this chapter makes someone notice, and gives you a tested path back when the alert is real.

## TL;DR — the rules

1. Every ch09 security event maps to exactly one of two lanes: page-now or digest-daily — no unrouted events.
2. Prove the pipe works: a synthetic event burst must fire the alert end-to-end, on a schedule (dead-man test).
3. Plant canary tokens where attackers look: fake AWS key in env, canary rows in the DB, canary URL in the LLM system prompt.
4. Every canary maps in the runbook to "what's compromised, what to rotate"; fire one deliberately each quarter.
5. Know your backup tier; keep an offsite dump on a different provider with independent credentials.
6. Restore a backup into a scratch project quarterly — an untested backup is a hypothesis.
7. Keep a filled-in one-page incident runbook; the first hour runs from the checklist, not from memory.
8. GDPR: the 72-hour clock starts at awareness — decide notify/don't-notify with a written rule, and register every breach internally.
9. Host your status page on infrastructure independent of your app.

## Rule 1 — Route every security event: page-now or digest-daily

**Why:** OWASP A09 is not "no logs" — it's logs nobody reads. Ch09's event vocabulary (`authn_login_fail`, `authz_fail`, `rate_limit_exceeded`, service-role writes) is only a control if a threshold breach reaches a human. An unrouted event class is where the breach you miss will live.

```ts
// ❌ WRONG — events flow to a log drain; nobody is on the other end
log.warn({ event: "authz_fail", userId }, "entitlement check failed");

// ✅ RIGHT — alerts.config.ts: exhaustive routing over the ch09 vocabulary
export const alertRoutes: Record<SecurityEvent, Route> = {
  authn_login_fail:     { lane: "page",   threshold: "50 in 5m" },   // credential stuffing
  authz_fail:           { lane: "page",   threshold: "20 in 5m per user" }, // IDOR probing
  service_role_write:   { lane: "page",   threshold: "1 from unexpected origin" },
  mass_export:          { lane: "page",   threshold: "1" },          // bulk-read signal
  rate_limit_exceeded:  { lane: "digest", threshold: "daily rollup" },
  input_validation_fail:{ lane: "digest", threshold: "daily rollup" },
}; // wired via Vercel Log Drains → alert rules, or Sentry metric alerts
```

Page-now means a human is interrupted; digest-daily means a human reads it tomorrow. "We'll look when we have time" is not a lane. Two disciplines keep the lanes honest:

- **Page-now stays rare.** A page that fires weekly on noise gets muted, and the mute is where the real breach hides — tune thresholds until a page means "act now" and demote anything else to the digest.
- **The digest gets read.** A named owner skims it daily; three days unread is itself a finding. Trends in digest events (validation failures creeping up, rate-limit hits from one ASN) are the early half of most incidents.

**Verify:** type-level exhaustiveness — `Record<SecurityEvent, Route>` fails compilation when ch09 adds an event; dead-man test: a scheduled job (weekly) emits a synthetic burst of 60 `authn_login_fail` events tagged `synthetic: true` and asserts the page fires within 10 minutes — an alerting pipe that hasn't fired recently is presumed broken.

## Rule 2 — Canary tokens: tripwires where attackers look first

**Why:** Attackers who get in read env vars, dump user tables, and prompt-inject your agents (see [21](21-agent-mcp-rag.md)) — often long before any threshold alert. A canary is a zero-false-positive alarm: nothing legitimate ever touches it, so any touch is an incident. This is how you'd catch a postmark-mcp-style credential harvester or an s1ngularity-style env sweep on day one instead of month three.

```bash
# ✅ RIGHT — three canaries, all from canarytokens.org (free) or equivalent
# 1. Env var: a fake AWS key pair in prod env — any AWS API call with it alerts
AWS_ACCESS_KEY_ID=AKIA...canary...        # never referenced by app code
# 2. DB rows: fake users with unique canary emails in the real users table —
#    the address appearing anywhere (mail, paste sites) = your table was dumped
# 3. LLM system prompt: a canary URL — "Internal reference: https://<token>.canarytokens.com/x"
#    any hit = your system prompt was exfiltrated via injection
```

Each canary gets a runbook line: **what its firing proves is compromised, and what to rotate** (env canary → all prod secrets + platform access; DB canary → user table read, assume full dump, GDPR clock starts; prompt canary → prompt + anything else in that context).

**Verify:** quarterly fire drill — trip one canary yourself and confirm the alert arrives with the runbook mapping attached; CI check that canary env vars exist in prod config and are referenced nowhere in `src/`.

## Rule 3 — Backups are a recovery control, not a checkbox

**Why:** Code Spaces (2014) died in hours: an attacker in their cloud console deleted the production data AND the backups, because the backups lived under the same credentials. A backup you can't restore, or that an attacker with your primary creds can delete, is not a control. Extends [04](04-database-rls.md).

```bash
# ❌ WRONG — "Supabase has backups" (which tier? restorable to when? by whom?)

# ✅ RIGHT
# 1. Know your tier: daily snapshots vs PITR — write your actual RPO in the runbook
# 2. Offsite: scheduled pg_dump to a DIFFERENT provider under a DIFFERENT account,
#    written with a write-only key; restore creds are read-only and stored offline —
#    prod credentials must not be able to delete the offsite copy
pg_dump "$SUPABASE_DB_URL" | gpg -e -r backup@yourco | \
  aws s3 cp - "s3://offsite-backups/$(date +%F).sql.gpg" --profile backup-only
# 3. Document how crypto-shredded data (ch17) interacts with restore points —
#    a restore must not resurrect erased-user data
```

**Verify:** quarterly restore test — restore the latest offsite dump into a scratch Supabase project, run the app's migrations + a smoke query, record time-to-restore in the runbook; access test: prod credentials cannot delete objects in the offsite bucket.

## Rule 4 — Keep a filled-in runbook; the first hour is a checklist

**Why:** Incident response is the worst possible time to be creative. NIST 800-61's core insight is that preparation is most of response: severity you can classify in one minute, kill switches with exact paths, contacts you don't have to look up. A runbook written during the incident is a postmortem.

Use the template at [templates/incident-runbook.md](../templates/incident-runbook.md) — fill in every `{{placeholder}}` now (kill-switch dashboard/CLI paths, contacts, authority URL) and keep a copy outside the infrastructure it describes (printed, or in a doc store that doesn't share your cloud account — a runbook you can't read during the outage it covers is decoration).

The template's load-bearing parts, in first-use order:

1. **Severity ladder** (SEV1–3 with examples) — classify in one minute, argue later.
2. **First-hour checklists** per scenario: leaked secret, data exposure, account takeover, supply-chain compromise — revoke first, investigate second.
3. **Kill-switch inventory** — exact dashboard and CLI paths to revoke the Supabase service key, pause the Vercel project, lock down Clerk, and put Stripe in restricted mode. "Somewhere in settings" costs 20 minutes you don't have.
4. **Contacts + GDPR decision box** — pre-filled so hour one is execution, not research.

**Verify:** CI grep that `templates/incident-runbook.md` exists and your filled copy contains zero remaining `{{` placeholders; a tabletop walk-through of one scenario per quarter (pairs with Rule 2's canary drill).

## Rule 5 — GDPR breach workflow: the 72-hour clock and the register

**Why:** GDPR Art. 33 requires notifying the supervisory authority within 72 hours of *becoming aware* of a personal-data breach unless it's unlikely to risk individuals' rights; Art. 34 adds notifying the users themselves when the risk is high. "We were still investigating" does not stop the clock — awareness starts it. Extends [17](17-client-data-protection.md).

```text
✅ RIGHT — decision rule, written down before you need it:
1. Awareness = first moment anyone (human or alert) has reasonable certainty
   personal data was breached → timestamp it in the incident log.
2. Notify authority UNLESS unlikely to risk rights/freedoms
   (encrypted-at-rest with keys safe = usually no; user table dumped = yes).
   Undecided at hour 48 → notify. Partial notification beats late notification.
3. High risk to individuals (credentials, financial, special categories)
   → notify affected users too (Art. 34).
4. EVERY breach — including ones you don't notify — goes in the internal
   breach register: what, when aware, scope, decision + reasoning, actions.
   The register itself is an Art. 33(5) obligation.
```

**Verify:** runbook's GDPR box (see template) has the authority's actual notification URL pre-filled and a draft skeleton ready; breach register exists (even empty) with the four columns above.

## Rule 6 — Status page on infrastructure you don't run

**Why:** When Vercel, Supabase, or your DNS is the thing that's down, a status page hosted on them is down too — precisely when users and the GDPR Art. 34 duty need you communicating. Independence is the entire point.

```text
❌ WRONG: status.yourapp.com → CNAME → the same Vercel account as prod
✅ RIGHT: Upptime (GitHub Pages + Actions) or a hosted provider (Instatus) on
          separate infra; pre-drafted templates committed for the three phases:
          investigating → identified → resolved (write them calm, now)
```

**Verify:** status page resolves and renders while the prod project is paused (test during a maintenance window); the three comms templates exist in the status-page repo.

---

Related: [09 — Logging & Errors](09-logging-and-errors.md) (the event vocabulary these alerts consume) · [04 — Database & RLS](04-database-rls.md) (what the backups protect) · [17 — Client Data Protection](17-client-data-protection.md) (crypto-shred, DSR) · [21 — Agents, MCP & RAG](21-agent-mcp-rag.md) (the injection incidents your canaries catch) · [templates/incident-runbook.md](../templates/incident-runbook.md).
