# Checklist — New Feature

Before marking any feature complete.

## Data layer
- [ ] Every new table: RLS enabled + policies (SELECT/INSERT/UPDATE incl. WITH CHECK/DELETE) **in the same migration** ([04](../rules/04-database-rls.md))
- [ ] Tenant/user scoping column present and non-nullable where relevant ([04](../rules/04-database-rls.md))
- [ ] Integrity enforced by constraints (UNIQUE/CHECK/FK), not just app code ([04](../rules/04-database-rls.md))
- [ ] Counters/credits/quotas updated atomically (`UPDATE ... WHERE ... RETURNING`), never read-modify-write ([04](../rules/04-database-rls.md))

## Endpoints
- [ ] [`new-endpoint.md`](new-endpoint.md) run for **each** new route, action, and webhook

## Secrets & config
- [ ] New env vars added to boot-time validation and `.env.example` (never a real value) ([05](../rules/05-secrets-and-env.md))
- [ ] Nothing secret carries a client prefix (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`) ([05](../rules/05-secrets-and-env.md))

## Credentials & tokens (if the feature touches them)
- [ ] Passwords: Argon2id/bcrypt server-side; tokens: `crypto.randomBytes(32)+`, stored hashed, single-use, TTL ([06](../rules/06-hashing-and-tokens.md))
- [ ] Any secret comparison is timing-safe ([06](../rules/06-hashing-and-tokens.md))

## Files & external calls (if applicable)
- [ ] Uploads: magic-byte validation, size cap, private bucket, randomized key ([11](../rules/11-file-uploads.md))
- [ ] No fetch of user- or LLM-supplied URLs without the SSRF validator ([13](../rules/13-ssrf-and-llm.md))
- [ ] LLM output schema-validated before use; never rendered as raw HTML ([13](../rules/13-ssrf-and-llm.md))

## Client data (if the feature touches PII)
- [ ] No production/client data in fixtures, seeds, notebooks, or the repo at all — Faker or anonymized exports only ([17](../rules/17-client-data-protection.md))
- [ ] New log lines checked against the do-not-log list; PII fields covered by logger redaction paths ([17](../rules/17-client-data-protection.md))
- [ ] No identifiers in new URLs; no PII in localStorage or client bundle ([17](../rules/17-client-data-protection.md))
- [ ] LLM calls send task-necessary, pseudonymized fields only ([17](../rules/17-client-data-protection.md))
- [ ] New PII columns: retention decided, encryption considered, added to the subprocessor/deletion map ([17](../rules/17-client-data-protection.md))

## Dependencies
- [ ] Every new package verified on the registry before install; lockfile committed ([14](../rules/14-supply-chain.md))

## Verification
- [ ] Security test suite extended for the new surface and green ([15](../rules/15-testing-verification.md))
- [ ] No security control was weakened/disabled to make anything pass — if one was, it's flagged for human review
