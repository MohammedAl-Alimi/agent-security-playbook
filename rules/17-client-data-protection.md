# 🧬 Client Data Protection

Client data leaks through two doors: into git (dumps, fixtures, notebooks) and into everything around the app (logs, error trackers, analytics, LLM APIs, dev copies). Both are one `git add .` or one `console.log(user)` away. Full research with all sources: [research/client_data_protection_findings.md](../research/client_data_protection_findings.md).

## TL;DR — the rules

1. Production/client data never enters a repository — fixtures and demos use Faker-generated or anonymized data only.
2. Ignore data-shaped artifacts by default and enforce with hooks (large-file check, nbstripout, gitleaks/TruffleHog with custom PII rules).
3. Client data committed to git is a disclosure incident, not a cleanup task: rotate, notify, then rewrite history with git-filter-repo.
4. Maintain a do-not-log list enforced by logger-level redaction; verify with a canary test.
5. Error trackers and session replay run scrub-by-default: `sendDefaultPii` off, `beforeSend` scrubber, mask-all replay.
6. Identifiers never go in URLs — a URL is broadcast to logs, Referer headers, and analytics.
7. Pseudonymize and minimize before any LLM API call; get retention terms in writing — "not trained on" ≠ "not retained."
8. Prod data stays in prod: dev/staging/CI get anonymized dumps only, exported already-masked.
9. Retention is a scheduled job that actually deletes (verified by a test); sensitive columns use envelope encryption so crypto-shredding reaches backups; deletion fans out to every subprocessor.
10. No PII in localStorage, client bundles, or source maps — the bundle ships to every visitor.

## Rule 1 — Production data never enters a repo

**Why:** MedData employee commits put patient records (names, SSNs, diagnoses) in public GitHub, where they were archived into the Arctic Code Vault — permanently beyond deletion. A 2020 sweep found ~150,000–200,000 patients' PHI across nine healthcare orgs' public repos. Private repos don't fix this: Red Hat's 2025 breach turned customer reports stored in repos into breach payload.

```bash
# ❌ WRONG — "realistic" fixtures from prod
pg_dump prod_db > seed.sql && git add seed.sql

# ✅ RIGHT — generated data, seeded for reproducibility
# JS: @faker-js/faker (the maintained fork)   Python: joke2k/faker
faker.seed(42); const user = { name: faker.person.fullName(), email: faker.internet.email() };
```

Jupyter special case: executed cell outputs (DataFrame previews, SQL results) are serialized into the `.ipynb` file — a `SELECT * FROM customers` becomes a permanent PII snapshot in history. Install [nbstripout](https://github.com/kynan/nbstripout) as a git filter in any repo with notebooks.

**Verify:** CI job greps fixtures/seeds for real-customer canaries (a known test email domain of real users, phone prefixes); notebooks checked for empty `outputs` arrays.

## Rule 2 — Ignore data artifacts by default, enforce with hooks

**Why:** `.gitignore` is a seatbelt, not a scanner — it doesn't untrack already-committed files, `git add -f` overrides it, and it misses `customers_final_v2.xlsx`. GitHub push protection blocks only supported *credential* patterns; a customers.csv sails through.

```gitignore
# ✅ data-shaped artifacts, in every repo template
data/
*.csv
*.sqlite*
*.db
*.dump
*.sql
*.sql.gz
*.bak
*.log
.env*
!.env.example
.DS_Store
.ipynb_checkpoints/
```

Layer hooks on top via [pre-commit](https://pre-commit.com/): `check-added-large-files` (catches dumps regardless of name), [gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog) — extended with custom rules for your PII shapes (customer email domains, IBAN, national-ID formats), because stock rulesets detect credentials, not PII. Run the same scan in CI over full history; client-side hooks are advisory.

**Verify:** the pre-commit config and CI scan job exist and run; a test commit containing a canary PII string is rejected.

## Rule 3 — A committed leak is an incident, not a cleanup

**Why:** git is content-addressed — deleting a file in a new commit leaves every blob reachable via history, reflogs, clones, forks, and `refs/pull/*`. Public pushes are scraped within minutes. GitHub's own guidance: rotate/revoke *first*, then rewrite.

Order of operations ([GitHub docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)):
1. Rotate every credential in the leaked content; for customer data, trigger your disclosure/notification process (GDPR clocks start now).
2. Rewrite with [git-filter-repo](https://github.com/newren/git-filter-repo) ≥ 2.47 `--sensitive-data-removal`.
3. Contact GitHub Support to purge cached views and PR refs; force-push and make every collaborator re-clone (a stale clone re-pushes the data).
4. Enumerate forks/mirrors; assume archives exist.

**Verify:** post-remediation, `trufflehog git file://. --no-verification` over the rewritten history finds nothing; the incident is logged with rotation timestamps.

## Rule 4 — Do-not-log list, enforced at the logger

**Why:** Facebook logged plaintext passwords of 200–600M users, searchable by ~20,000 employees — the Irish DPC fined Meta **€91M** over it. Twitter logged passwords pre-hash and reset 336M accounts. And AI-generated code fails log-safety constantly (Veracode: 88% failure on log injection). The [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) rule: log *events*, never *payloads*.

```ts
// ❌ WRONG — whole objects into logs
logger.info(`login attempt: ${JSON.stringify(req.body)}`);

// ✅ RIGHT — structured events + logger-level redaction (pino)
const logger = pino({
  redact: { paths: ['*.password', '*.token', '*.email', 'req.headers.authorization', 'user.ssn'], remove: true },
});
logger.info({ event: 'authn_login_fail', userId: hash(userId) });
```

Do-not-log list minimum: passwords (any form), tokens/session IDs in full, card numbers, government IDs, free-text user content, full request bodies. Log retention is GDPR storage-limitation liability — cap it. See [logging & errors](09-logging-and-errors.md) for the interceptor pattern this plugs into.

**Verify:** canary test — submit a unique marker value through signup/login, then grep every log sink for it; zero hits.

## Rule 5 — Error trackers and session replay scrub by default

**Why:** Sentry events carry stack traces, breadcrumbs, headers, and query strings — sensitive data hides in all of them. Session replay records the page itself; unmasked, it's a keylogger with a dashboard.

```ts
// ✅ Sentry: PII off, client scrub, masked replay
Sentry.init({
  sendDefaultPii: false,                      // the default — never flip it casually
  beforeSend(event) { delete event.user?.email; return scrub(event); },
  integrations: [Sentry.replayIntegration({ maskAllText: true, blockAllMedia: true })],
});
```

Enable Sentry's server-side scrubbing as the backstop. Same posture in LogRocket (`inputSanitizer`, `data-private`) and Fullstory ("Private by Default"): mask everything, then allowlist reviewed elements — never capture-then-blocklist.

**Verify:** trigger a synthetic error containing a canary email; confirm it's absent from the stored event. Play back your own checkout-flow replay and read every visible string.

## Rule 6 — Identifiers never go in URLs

**Why:** a URL propagates to access logs, CDN logs, browser history, `Referer` headers, and every analytics tool recording `page_location`. Sending PII to Google Analytics violates its terms — the classic leak is an email in a query string after a GET form.

```text
❌ /reset?email=jane@client.com          ✅ POST body + opaque single-use token
❌ /users/jane@client.com/profile        ✅ /users/usr_8f2k1/profile
```

**Verify:** crawl your analytics page-path report for `@` and long-numeric patterns; grep route definitions for email/name path params.

## Rule 7 — Minimize and pseudonymize before LLM calls

**Why:** OWASP ranks Sensitive Information Disclosure #2 for LLM apps (LLM02:2025). Provider defaults: API data is typically *not trained on* but *is retained* (~30 days for abuse monitoring at Anthropic and OpenAI); zero-data-retention is a negotiated agreement, not a checkbox — and policies changed during 2026, so re-verify quarterly.

```ts
// ❌ WRONG — whole customer record into the prompt
const summary = await generateText({ prompt: `Summarize: ${JSON.stringify(customer)}` });

// ✅ RIGHT — task-necessary fields only, identifiers tokenized, re-substituted after
const map = pseudonymize(customer);            // {"Jane Doe" -> "CUSTOMER_1", ...}
const out = await generateText({ prompt: `Summarize: ${map.text}` });
return map.restore(out);
```

Treat the LLM provider as a subprocessor (DPA in place); never send credentials, government IDs, or health/financial data without ZDR + the right agreement. LLM prompt/response logs are a second copy of the PII — run them through the same redaction as Rule 4. See [SSRF & LLM apps](13-ssrf-and-llm.md) for the output side.

**Verify:** audit one day of outbound LLM payloads for names/emails/IDs; retention terms for each provider are linked in the repo docs with a review date.

## Rule 8 — Prod data stays in prod

**Why:** the classic leak chain: `pg_dump` → laptop → staging box with weak auth → or straight into git (Rule 1). Anonymize **at export time** so a raw dump never exists outside the prod trust boundary.

```bash
# ✅ anonymized dev copy — Greenmask (pg_restore-compatible, deterministic)
greenmask dump --config greenmask.yml   # transformers mask name/email/etc. during dump
# or: PostgreSQL Anonymizer (Dalibo) — SECURITY LABEL masking rules + anonymous dumps
```

(Both verified maintained; Snaplet shut down 2024, Neosync archived 2025 — don't reach for them.) CI never touches real customer records; GitHub Actions masks only *registered* secrets (`::add-mask::`), and derived values leak. Backups are prod data with weaker controls — same encryption, access logging, and deletion scope as the live DB. Shared `.env` files in chat are an unaudited distribution channel — use a secret manager with CLI injection (Infisical, Doppler).

**Verify:** query staging/dev for any real customer email → zero rows; CI logs searched for canary values.

## Rule 9 — Retention as code, crypto-shredding, deletion fan-out

**Why:** GDPR Art. 5(1)(e) makes "we keep everything forever" a liability, and Art. 17 erasure doesn't stop at your DB — the error tracker, replay tool, analytics, email provider, LLM provider, log store, and backups all hold copies. A policy PDF deletes nothing.

```sql
-- ✅ retention as a scheduled job that actually deletes, with failure alerting
DELETE FROM audit_events WHERE created_at < now() - interval '180 days';
```

Sensitive columns: envelope encryption (per-record data key, AES-256-GCM, KMS-wrapped — see [hashing & tokens](06-hashing-and-tokens.md) Rule 7); destroying the data key ("crypto-shredding") makes deletion reach backups for free. Maintain a subprocessor inventory (who holds which fields, their retention, their deletion API) — that list is your leak map, and your DSR pipeline fans deletions out across it.

**Verify:** insert a back-dated record and confirm the job removes it on schedule; run a full deletion for a test user and check each third-party console.

## Rule 10 — No PII in browser storage, bundles, or source maps

**Why:** one XSS reads all of localStorage; bundles and uploaded source maps ship to every visitor, including any "test" fixture with real emails or internal endpoints baked in.

```ts
// ❌ WRONG                                    // ✅ RIGHT
localStorage.setItem('user', JSON.stringify({  // identity in httpOnly session cookie;
  email, token }));                            // render PII from server responses only,
                                               // cache at most non-identifying prefs
```

**Verify:** build the client bundle and grep the output (and source maps) for `@`, canary values, and internal hostnames; check `Application → Local Storage` in a logged-in session for anything identifying.

---

Related: [secrets & env](05-secrets-and-env.md) (credential-shaped leaks), [logging & errors](09-logging-and-errors.md) (the interceptor this feeds), [caching](16-caching-cdn.md) (PII in shared caches), [self-verification](15-testing-verification.md) (where the canary tests live).
