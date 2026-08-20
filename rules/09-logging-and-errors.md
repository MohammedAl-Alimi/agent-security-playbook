# 📋 Logging & Error Handling

Errors deny by default and leak nothing; logs are structured JSON with PII redacted, security events named per OWASP, and every sensitive mutation leaves an audit row.

## TL;DR — the rules

1. Every route/action wraps its body in an interceptor: log the full error server-side with a request ID, return a generic message + that ID to the client — never `err.message`, stacks, or DB error text (A10:2025).
2. A catch block around auth or validation FAILS CLOSED — an error denies (401/403/500), it never falls through to success.
3. Log structured JSON (pino) with a `redact` config covering auth headers, cookies, passwords, tokens, keys, and emails.
4. Never interpolate user input into log message strings — pass it as structured fields with a length cap (Veracode: LLMs fail log injection 88% of the time).
5. Name security events per the OWASP Logging Vocabulary: `authn_login_fail`, `authz_fail`, `input_validation_fail`, `rate_limit_exceeded`.
6. Every sensitive mutation writes an append-only audit row (actor, action, target, requestId, timestamp) in the same transaction.
7. Sentry: `sendDefaultPii: false` and a `beforeSend` that strips user, cookies, authorization headers, and query strings.
8. Rich error detail is a dev-only behavior; production clients get the generic message + correlation ID, enforced by code, not discipline.

## Rule 1 — The error interceptor: generic message + request ID out, full error in

OWASP A10:2025 (Mishandling of Exceptional Conditions) is a new Top-10 category because this fails constantly. Next.js masks RSC/Server Action errors in prod with a `digest` hash — but **Route Handlers get no automatic masking**: an uncaught Postgres error returns chatty text naming tables, columns, and constraints to the client.

```ts
// ❌ WRONG — Postgres error text (table names, constraints) goes to the attacker
export async function POST(req: Request) {
  try { return Response.json(await createTask(req)); }
  catch (err) { return Response.json({ error: (err as Error).message }, { status: 500 }); }
}

// ✅ RIGHT — full context server-side, opaque handle client-side
export async function POST(req: Request) {
  const requestId = req.headers.get('x-vercel-id') ?? crypto.randomUUID();
  const log = logger.child({ requestId });
  try { return Response.json(await createTask(req)); }
  catch (err) {
    log.error({ err }, 'task_create_failed');
    return Response.json({ error: 'Internal error', requestId }, { status: 500 });
  }
}
```

For Server Actions, use next-safe-action's `handleServerError` allowlist: return the real message only for `instanceof ActionError`, else `DEFAULT_SERVER_ERROR_MESSAGE`. In error boundaries, display `error.digest` as the support code — never `error.message`. Ship both `error.tsx` and `global-error.tsx`.

**Verify:** integration test forces a DB error (duplicate key, bad column) → HTTP body contains no stack frames, no SQL text, no `relation "` — just the generic message and an ID.

## Rule 2 — Fail closed: an error must deny, not allow

Threat-model row #16: AI-generated catch blocks routinely swallow errors and continue, converting an auth outage into an auth bypass. next-forge (verified) no-ops its entire security package when `ARCJET_KEY` is missing.

```ts
// ❌ WRONG — Redis down = everyone is authorized
let allowed = true;
try { allowed = await checkEntitlement(userId); } catch { /* ignore */ }
if (allowed) return sensitiveData();

// ✅ RIGHT — the catch path is a denial, logged as a security event
try {
  if (!(await checkEntitlement(userId))) throw new AuthzError();
} catch (err) {
  log.warn({ event: 'authz_fail', userId, requestId }, 'entitlement check failed-closed');
  return Response.json({ error: 'Forbidden', requestId }, { status: err instanceof AuthzError ? 403 : 503 });
}
```

Same rule for validation (`Schema.parse` throwing must 400, never default), rate limiters (see [06 — Rate Limiting](./06-rate-limiting.md)), and missing security env vars (boot failure, never a silent no-op). Logging failures are the one exception: swallow them — a broken log pipeline must never crash the request.

**Verify:** grep for `catch` blocks in auth/entitlement/validation paths — each must `throw`, `return` an error status, or `redirect`; a test stubs the dependency to throw and asserts the request is denied.

## Rule 3 — Structured JSON with redaction (pino)

Redaction is the PII control. Baseline starters ship `console.log(evt.data)` in webhook handlers — a GDPR incident per `user.created` event. On Vercel: plain JSON to stdout, **no transports in production** (worker-thread flushes are lost on function freeze), `serverExternalPackages: ['pino', 'pino-pretty']` in next.config, pino-pretty dev-only.

```ts
// ✅ RIGHT — lib/logger.ts
import pino from 'pino';
export const logger = pino({
  redact: {
    paths: ['req.headers.authorization', 'req.headers.cookie',
            '*.password', '*.token', '*.apiKey', '*.secret', '*.email'],
    censor: '[REDACTED]',
  },
  ...(process.env.NODE_ENV === 'development' && { transport: { target: 'pino-pretty' } }),
});
```

Prefer explicit paths (~2% overhead) over deep wildcards (~50%); never derive redact paths from user input. On Fluid Compute one instance serves many concurrent requests — use per-request `logger.child({ requestId, userId })` (or AsyncLocalStorage), never module-scope mutable context, and `waitUntil()` for telemetry flushes. Never log: session IDs, tokens, `process.env`, raw webhook payloads (`evt.type` + `evt.data.id` only), card/health data.

**Verify:** unit test logs an object containing `password`/`token`/`email` fields into a stream and asserts `[REDACTED]`; grep `console.log` in `app/`/`src/` → zero outside dev scripts.

## Rule 4 — Log injection: structured fields, never string interpolation

Veracode's 2025 GenAI report: LLMs fail log-injection tasks **88% of the time**. Interpolating raw input lets an attacker inject CRLF sequences that forge log lines (`"admin logged in"`) or corrupt log parsers.

```ts
// ❌ WRONG — attacker-controlled newlines forge log entries
log.info(`login failed for ${username}`);

// ✅ RIGHT — JSON escaping is the injection control; cap length
log.warn({ event: 'authn_login_fail', username: String(username).slice(0, 512) }, 'login failed');
```

```python
# ✅ RIGHT — Python: structured extra, never f-strings with user input
logger.warning("login failed", extra={"event": "authn_login_fail", "username": username[:512]})
```

**Verify:** Semgrep rule flagging template literals / f-strings containing request-derived variables inside logger calls → zero findings.

## Rule 5 — Security event vocabulary + audit trail

Per the OWASP Logging Cheat Sheet, log authn success/failure, authz failures, validation failures, rate limiting, and privileged actions — with when/where/who/what — under stable names (`authn_login_success`, `authn_login_fail`, `authz_fail`, `input_validation_fail`, `rate_limit_exceeded`) so repeated failures are queryable for alerting (A09:2025 is Security Logging & Alerting Failures).

Separately, every sensitive mutation (role/billing change, deletion, export, **any service-role write**) writes an audit row in the same transaction:

```sql
-- ✅ RIGHT — append-only: RLS on, no app write/update/delete policies (inserted via trigger or definer fn)
create table audit_log (
  id bigint generated always as identity primary key,
  actor text not null,          -- auth.jwt()->>'sub' with Clerk, never auth.uid()
  action text not null, target text not null,
  old_data jsonb, new_data jsonb,  -- pre-redacted
  request_id text, created_at timestamptz not null default now()
);
alter table audit_log enable row level security;  -- and: zero UPDATE/DELETE policies
```

supa_audit is archived (Feb 2025) — vendor its trigger SQL rather than depending on it.

**Verify:** pgTAP asserts `audit_log` has RLS enabled and no UPDATE/DELETE policies; integration test performs a role change and asserts exactly one audit row with the acting user.

## Rule 6 — Error telemetry without PII (Sentry) and the dev/prod split

`instrumentation.ts` exporting `onRequestError = Sentry.captureRequestError` is the only hook that sees Server Action, RSC, and middleware errors. But telemetry is exfiltration if unscrubbed.

```ts
// ✅ RIGHT — sentry.server.config.ts
Sentry.init({
  sendDefaultPii: false,
  beforeSend(event) {
    delete event.user;
    if (event.request) {
      delete event.request.cookies;
      delete event.request.headers?.['authorization'];
      event.request.query_string = undefined;
    }
    return event;
  },
});
```

The dev/prod asymmetry is the #1 trap: in dev, full error messages reach the client from RSC/Server Actions, so leaks are invisible until production behaves differently — or worse, a route handler leaks in both. The split must be structural (Rule 1's interceptor + Next's prod masking), never `if (isDev)` sprinkled per route.

**Verify:** CI runs the Rule 1 leak test against a **production build** (`next build && next start`), not the dev server.

---

Next: [10 — Headers, CSP & CORS](./10-headers-csp-cors.md) · Capstone: [15 — Self-Verification](./15-testing-verification.md)
