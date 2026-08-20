# Checklist — New Endpoint (route handler / server action / webhook)

Run through this for **every** new HTTP-reachable unit. Server actions count — they are public POST endpoints.

## Identity & access
- [ ] Calls `auth()` (or equivalent) **inside the handler** — not relying on middleware ([01](../rules/01-authentication.md))
- [ ] Authorization checked against the **specific resource**: query filters by caller/tenant ID, 404 on zero rows ([02](../rules/02-authorization.md))
- [ ] No identity/role/price field accepted from the request body — derived from session/server ([02](../rules/02-authorization.md), [12](../rules/12-payments.md))

## Input
- [ ] Body, params, searchParams, and relevant headers parsed through a **strict** schema before any use ([03](../rules/03-input-validation.md))
- [ ] No raw input object spread into a DB write ([03](../rules/03-input-validation.md))

## Abuse
- [ ] Rate limited if it mutates, costs money (LLM/email), or touches auth — keyed on `userId ?? ip`, failing closed ([07](../rules/07-rate-limiting.md))
- [ ] Idempotency handled if double-submit would double-charge or double-create ([07](../rules/07-rate-limiting.md), [12](../rules/12-payments.md))

## Webhooks only
- [ ] Signature verified over the **raw body** before parsing; 400 on failure ([08](../rules/08-webhooks.md))
- [ ] Missing signing secret fails boot/build — no silent 200 ([08](../rules/08-webhooks.md))
- [ ] Processing idempotent on event ID ([08](../rules/08-webhooks.md))

## Output & errors
- [ ] Errors return generic message + request ID; details go to structured logs only ([09](../rules/09-logging-and-errors.md))
- [ ] Catch blocks fail closed ([09](../rules/09-logging-and-errors.md))

## Caching
- [ ] Personalized/authenticated response → `Cache-Control: private, no-store`; only allowlisted identical-for-everyone routes are cacheable ([16](../rules/16-caching-cdn.md))
- [ ] Any `unstable_cache`/`use cache`/Redis entry holding user data has the user/tenant ID in its key ([16](../rules/16-caching-cdn.md))
- [ ] No auth/entitlement decision is cached ([16](../rules/16-caching-cdn.md))

## Verification
- [ ] Endpoint added to the 401/403 table-driven security test in the same PR ([15](../rules/15-testing-verification.md))
