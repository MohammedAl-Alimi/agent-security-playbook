# 📨 Webhooks

A webhook endpoint is an unauthenticated public POST route: the signature over the raw body is its only authentication, and it fails closed.

## TL;DR — the rules

1. Verify the provider signature over the RAW body before any parsing or side effect — 400/401 on failure.
2. A missing signing secret is a build/boot failure or 5xx — never a silent 200.
3. Keep the SDK's timestamp tolerance (Stripe default 5 min) — never `tolerance: 0`, never unbounded.
4. Process idempotently: insert the event id into a `processed_events` table (PRIMARY KEY) before side effects; duplicates exit early.
5. Return 2xx only after durable handoff — verified, deduped, and persisted/enqueued.
6. Never trust payload fields for money or entitlements — re-fetch current state from the provider's API.
7. After verification, parse the event through a discriminated union on `event.type`; unhandled types get 200 with no side effects.
8. Sign your own outbound webhooks with HMAC (timestamp + body), and document verification for consumers.

## Rule 1 — Signature over the raw body, before everything

Threat-model row #7: unverified `JSON.parse(req.body)` is near-universal in generated Clerk/Stripe/Resend handlers. Without verification, anyone who finds the URL forges `user.created` or `checkout.session.completed`. Verification must run over the **raw bytes** — any framework body parsing first (or re-serializing parsed JSON) breaks the HMAC.

```ts
// ❌ WRONG — parses first, never verifies
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') await fulfill(event.data.object);
  return Response.json({ received: true });
}

// ✅ RIGHT — Stripe: constructEvent over the raw text
export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature');
  if (!sig) return new Response('missing signature', { status: 400 });
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(await req.text(), sig, env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return new Response('invalid signature', { status: 400 }); // no details, no side effects
  }
  // ... Rules 4–7 below
}
```

Clerk (Svix) is one call that wraps the same discipline: `const evt = await verifyWebhook(req)` with `CLERK_WEBHOOK_SIGNING_SECRET` set; other Svix providers via the `svix` package. Python/FastAPI: pass `await request.body()` (raw bytes) to the provider's verify call — never the parsed model.

**Verify:** integration test posts a forged unsigned payload and a valid-body-wrong-secret payload → both 400/401 with zero DB writes; `npx clerk webhooks verify` / `stripe listen` pass end-to-end.

## Rule 2 — Missing secret = boot failure, never silent 200

Verified next-forge fail-open bug: its Stripe webhook returns **HTTP 200 "Not configured"** when `STRIPE_WEBHOOK_SECRET` is unset — Stripe marks every delivery successful and never retries, so billing events vanish silently in any environment where the env var is missing. Same class as its `if (!arcjetKey) return;` no-op.

```ts
// ❌ WRONG — next-forge pattern: provider thinks delivery succeeded forever
if (!process.env.STRIPE_WEBHOOK_SECRET) {
  return Response.json({ message: 'Not configured' }, { status: 200 });
}

// ✅ RIGHT — env module throws at build/boot (see 03, Rule 6); nothing to check in the route
import { env } from '@/env';   // t3-env: missing STRIPE_WEBHOOK_SECRET already failed `next build`
const secret = env.STRIPE_WEBHOOK_SECRET;
```

If a runtime guard must exist anyway, it returns 5xx so the provider retries and the failure is visible.

**Verify:** unset the secret and run `next build` (or boot the FastAPI app) → hard failure; grep webhook routes for `status: 200` inside any not-configured/except branch → zero.

## Rule 3 — Timestamp tolerance against replay

A captured signed payload is valid forever unless the timestamp is checked: signature schemes (Stripe, Svix) sign `timestamp.body` precisely so receivers can reject stale deliveries. Stripe's SDK enforces a 5-minute default tolerance — keep it.

```ts
// ❌ WRONG — disables replay protection entirely
stripe.webhooks.constructEvent(raw, sig, secret, 0 /* tolerance */);

// ✅ RIGHT — omit the argument; the default 300s tolerance is the control
stripe.webhooks.constructEvent(raw, sig, secret);
```

Tolerance bounds the replay window; the event-id dedupe in Rule 4 closes it completely (a replay inside 5 minutes is still a duplicate id).

**Verify:** grep webhook code for `tolerance` → either absent or ≥ the SDK default; test replays a valid signed payload with a 10-minute-old timestamp → 400.

## Rule 4 — Idempotency keyed on event id

Providers deliver at-least-once and **unordered** — duplicates are normal operation, not an edge case. An in-memory `Set` resets on every cold start; the dedupe store must be the database.

```ts
// ✅ RIGHT — claim the event id atomically before side effects (see 04, Rule 8)
const { rowCount } = await client.query(
  `insert into processed_events (event_id) values ($1) on conflict do nothing`,
  [event.id],
);
if (rowCount === 0) return Response.json({ received: true }); // duplicate: ack, do nothing
await handleEvent(event);
```

For fulfillment specifically, add `UNIQUE (checkout_session_id)` on the fulfillments table so even a bug upstream cannot grant twice.

**Verify:** `stripe trigger checkout.session.completed` twice with the same event → exactly one fulfillment row; pgTAP asserts the PRIMARY KEY/UNIQUE constraints exist.

## Rule 5 — 2xx only after durable handoff

A 2xx tells the provider "delete this event — never retry." Acking before the work is durable converts any crash into permanent data loss; conversely, slow handlers hit provider timeouts and cause duplicate storms.

```ts
// ❌ WRONG — ack first, work later; a crash after this line loses the event forever
res.status(200).end();
await syncUser(event.data);

// ✅ RIGHT — verify → dedupe → persist/enqueue durably → then 200
await enqueue('webhook-jobs', { id: event.id, type: event.type }); // durable queue or DB row
return Response.json({ received: true });
// unrecoverable-for-now failure? return 5xx and let the provider retry
```

Keep handlers fast: verify, dedupe, record, ack; heavy work runs from the queue/DB job.

**Verify:** kill the handler between verification and persistence in a test → provider retry (non-2xx) is observed; no code path returns 2xx before the insert/enqueue resolves.

## Rule 6 — Never trust payload fields for money

Events are snapshots: stale, reorderable, and — if any verification gap exists — forgeable. EnrichLead's paywall fell to a forged `?success=true` redirect in 72 hours; the same logic bug applies to trusting `amount_total` from a payload. The t3dotgg pattern: sync-don't-mutate — fetch CURRENT state from the API and overwrite your store.

```ts
// ❌ WRONG — grants whatever the snapshot (or forger) says
if (event.type === 'checkout.session.completed') {
  await grantCredits(event.data.object.metadata.userId, event.data.object.amount_total / 100);
}

// ✅ RIGHT — re-retrieve from the API; the event is only a trigger
const session = await stripe.checkout.sessions.retrieve(
  (event.data.object as Stripe.Checkout.Session).id, { expand: ['line_items'] });
if (session.payment_status === 'unpaid') return ok(); // ACH can complete unpaid
const userId = session.client_reference_id;           // identity from the session, never a cookie
await fulfillCheckout(session);                       // idempotent per Rule 4
```

**Verify:** test feeds a verified-but-stale event with tampered `amount_total`/`metadata` → fulfillment matches the API-fetched session, not the payload.

## Rule 7 — Discriminated-union parse after verification

The signature proves *who sent it*, not *what shape it is*. Parse the verified payload through a discriminated union on `event.type` (see [03 — Input Validation](./03-input-validation.md), Rule 5); allowlist handled types and mirror that list in the provider dashboard so you only receive what you handle.

```ts
// ✅ RIGHT
const Handled = z.discriminatedUnion('type', [
  z.object({ type: z.literal('user.created'), data: z.object({ id: z.string() }).loose() }),
  z.object({ type: z.literal('user.deleted'), data: z.object({ id: z.string() }).loose() }),
]);
const parsed = Handled.safeParse(evt);
if (!parsed.success) return Response.json({ received: true }); // unhandled type: ack, no side effects
```

**Verify:** grep webhook handlers for `event.data` / `evt.data` accesses outside the parsed result → zero; unhandled-type test asserts 200 with no DB writes.

## Rule 8 — Sign your outbound webhooks

If your app delivers webhooks to user-configured URLs, give consumers the same guarantees you demand: HMAC-SHA256 over `timestamp.body` with a per-endpoint secret, timestamp header, and documented verification. (User-configured destination URLs are also an SSRF sink — validate them per the SSRF chapter before fetching.)

```ts
// ✅ RIGHT
const ts = Math.floor(Date.now() / 1000);
const sig = crypto.createHmac('sha256', endpoint.secret).update(`${ts}.${body}`).digest('hex');
await safeFetch(endpoint.url, { method: 'POST', body,
  headers: { 'X-Webhook-Timestamp': String(ts), 'X-Webhook-Signature': `v1=${sig}` } });
```

**Verify:** consumer-side test recomputes the HMAC from the documented recipe and rejects a tampered body; secrets are per-endpoint and rotatable.

---

Related: [03 — Input Validation](./03-input-validation.md) · [04 — Database & RLS](./04-database-rls.md)
