# 💳 Payments & Billing

Money state lives at the provider and in webhook-written tables; the client never names a price, triggers a fulfillment, or holds an entitlement flag.

## TL;DR — the rules

1. Never fulfill from a client redirect or `?success=true` — fulfillment is webhook-driven only.
2. Verify the webhook signature over the raw body, then re-fetch the session/subscription from the provider API and check `payment_status` before granting anything.
3. Fulfillment is idempotent, keyed on the event/session ID in the database — replayed events grant exactly once.
4. Prices and amounts are server-side only: a Price-ID allowlist; reject any request body containing `amount`, `price_data`, or `currency`.
5. Check entitlements server-side on every gated request — a client flag or hidden button is not access control.
6. Handle the subscription lifecycle: `canceled`/`past_due`/payment-failed events revoke access, not just grant it.
7. Credits/quotas decrement in one atomic `UPDATE ... WHERE balance >= x RETURNING` — never SELECT-then-UPDATE.
8. Test-mode and live-mode keys never mix: separate env sets per environment, validated at boot.
9. Order math is server-owned: quantity is `z.number().int().positive().max(CAP)`, every derived number is recomputed server-side, currency is fixed by the Price ID, and a Postgres CHECK mirrors the bounds.

## Rule 1 — Fulfillment via webhook, never the redirect

EnrichLead (2025) shipped an AI-built paywall that granted subscriptions from the client-side success path; it was bypassed **from the browser console within 72 hours** of the founder's launch tweet, and the product shut down. The success URL is a GET any attacker can type.

```ts
// ❌ WRONG — /success?session_id=... grants the plan; curl grants it too
export default async function SuccessPage({ searchParams }: Props) {
  await grantPlan(user.id, searchParams.plan);   // forgeable
  return <ThankYou />;
}

// ✅ RIGHT — the webhook is the only writer; the success page just reads/synces
export async function POST(req: Request) {  // app/api/webhooks/stripe/route.ts
  const event = stripe.webhooks.constructEvent(
    await req.text(), req.headers.get('stripe-signature')!, env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'checkout.session.completed' ||
      event.type === 'checkout.session.async_payment_succeeded') {
    await fulfillCheckout(event.data.object.id);   // Rule 2/3
  }
  return Response.json({ received: true });
}
```

The success page may eagerly call the same `fulfillCheckout(sessionId)` as a latency optimization — because it's idempotent and re-verifies with Stripe, a forged call grants nothing. A missing `STRIPE_WEBHOOK_SECRET` is a boot failure or 5xx, **never 200** — next-forge's verified bug returns 200 "Not configured", so Stripe marks delivery successful and billing events vanish silently.

**Verify:** test hits `/success?session_id=cs_test_fake` (and calls `fulfillCheckout` with an unpaid session) → no entitlement row; boot without the webhook secret → process refuses to start.

## Rule 2 — Verify signature, then re-fetch and check payment_status

Two independent checks: the signature proves *Stripe sent it*; the API re-fetch proves *what is true now*. Stripe delivery is at-least-once and **unordered** — payload snapshots go stale, so fetch current state instead of trusting the event body. And ACH/delayed-payment sessions complete with `payment_status: 'unpaid'`.

```ts
// ✅ RIGHT — inside fulfillCheckout(sessionId)
const session = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items'] });
if (session.payment_status === 'unpaid') return;                  // completed ≠ paid
const userId = session.client_reference_id ?? session.metadata?.userId;
if (!userId) throw new Error('unattributable session');           // never the visitor's cookie
```

Keep the SDK's default 5-minute signature tolerance (never `tolerance: 0`); resolve WHO from `client_reference_id`/`metadata.userId` set at session creation — never from whoever is browsing the success page. See [08 — Webhooks](./08-webhooks.md) for raw-body and parsing rules.

**Verify:** unsigned/forged POST to the webhook → 400 with no side effects; a `stripe trigger checkout.session.completed` with `payment_status: unpaid` fixture → no grant.

## Rule 3 — Idempotent fulfillment keyed in the database

Stripe retries; attackers replay. Dedupe with the database (an in-memory Set resets on every cold start — threat-model row #18's cousin):

```sql
-- ✅ RIGHT — claim before side effects; second delivery hits the PK and no-ops
create table processed_events (event_id text primary key, created_at timestamptz default now());
create table fulfillments (checkout_session_id text unique, user_id text not null, ...);
```

```ts
const { rowCount } = await sql`
  insert into processed_events (event_id) values (${event.id}) on conflict do nothing`;
if (rowCount === 0) return Response.json({ received: true });   // already handled
```

**Verify:** `stripe trigger` (or replay a captured signed payload) the same event twice → exactly one fulfillment row, second response still 2xx.

## Rule 4 — Prices are server-side; the client picks a name, not a number

Threat-model row #12's sibling: AI code routinely turns a client integer into the charge amount. The client sends at most an enum; the server maps it to a provider Price ID.

```ts
// ❌ WRONG — client names its own price
const { amount, currency } = await req.json();
await stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: amount, currency, ... } }] });

// ✅ RIGHT — Zod enum → server-side allowlist of Price IDs; identity from auth()
const PRICES = { starter: 'price_1Abc...', pro: 'price_1Def...' } as const;
const { plan } = z.strictObject({ plan: z.enum(['starter', 'pro']) }).parse(await req.json());
const { userId } = await auth();
await stripe.checkout.sessions.create({
  line_items: [{ price: PRICES[plan], quantity: 1 }],
  client_reference_id: userId, customer: await getOrCreateCustomer(userId),
  mode: 'subscription', success_url: ..., cancel_url: ...,
});
```

Reject any body containing `amount`, `unit_amount`, `price_data`, `currency`, or a raw `price_...` string — `z.strictObject` makes them a 400 for free.

**Verify:** POST with `{"plan":"pro","amount":1}` or a tampered `price_...` → 400; grep checkout code for `price_data`/`unit_amount` fed from request input → zero.

## Rule 5 — Entitlements checked server-side on every gated request

A hidden upgrade button and a `isPro` client flag are rendering hints; the API behind them is one curl away (Clerk's `<Protect>`/`<PricingTable>` are explicitly rendering-only). Billing tables are written **only** by the webhook handler (service-role); RLS grants the owner SELECT and no write policies — so a compromised client can't self-upgrade.

```ts
// ✅ RIGHT — in the data layer, on every gated call
const sub = await db.query.subscriptions.findFirst({
  where: and(eq(subscriptions.userId, userId),
             inArray(subscriptions.status, ['active', 'trialing']),
             gt(subscriptions.currentPeriodEnd, new Date())),
});
if (!sub) throw new PaywallError();
// Clerk Billing equivalent: const { has } = await auth(); if (!has({ plan: 'pro' })) ...
```

**Verify:** curl every paid endpoint as a free user and as a cancelled user → 403; negative test lives in the regression suite ([15 — Self-Verification](./15-testing-verification.md)).

## Rule 6 — Lifecycle: revocation or you're giving it away

Grant-only integrations are the common AI omission: the app handles `checkout.session.completed` and nothing else, so cancelled and delinquent customers keep access forever. Handle `customer.subscription.updated`, `customer.subscription.deleted`, and `invoice.payment_failed` (Clerk Billing: `subscriptionItem.canceled/ended/pastDue`, `paymentAttempt.updated`). The robust shape is t3dotgg's sync-don't-mutate: one `syncStripeDataToKV(customerId)` that fetches CURRENT state from the API and overwrites your store, called from every relevant event — no per-event state machines to get wrong.

**Verify:** cancel a test subscription in the dashboard → after webhook delivery, the paid endpoint returns 403.

## Rule 7 — Race-safe credits: one atomic statement

Read-check-then-write has a ~1ms window PortSwigger's single-packet attack exploits reliably — parallel requests each read `balance: 1` and all pass the check.

```sql
-- ❌ WRONG: SELECT balance; if (balance >= cost) UPDATE ...   (double-spend window)

-- ✅ RIGHT — atomic claim in a SECURITY DEFINER RPC; belt-and-braces CHECK
update credits set balance = balance - $cost
  where user_id = $uid and balance >= $cost
  returning balance;                    -- zero rows = insufficient funds, deny
alter table credits add constraint balance_nonneg check (balance >= 0);
```

**Verify:** test fires 10 parallel spends exceeding the balance → total granted ≤ starting balance (see [15](./15-testing-verification.md)).

## Rule 8 — Test/live key separation

Live keys in dev (real charges from a test run) and test keys in prod (a `sk_test_` "payment" that grants real entitlements) are both boot-time-detectable. Encode the mode in env validation:

```ts
// ✅ RIGHT — in src/env.ts
STRIPE_SECRET_KEY: z.string().refine(
  (k) => process.env.VERCEL_ENV === 'production' ? k.startsWith('sk_live_') : k.startsWith('sk_test_'),
  'key mode must match environment'),
```

Webhook endpoints and secrets are also per-mode — a live endpoint must reject test-mode events (`event.livemode === false` in production → log and 2xx without side effects).

**Verify:** build with `sk_test_` in the production env set → build/boot fails; unit test feeds a `livemode: false` event to the prod handler → no fulfillment.

## Rule 9 — Order math: bounded quantities, recomputed totals

Quantity manipulation is the classic business-logic flaw (CWE-840, PortSwigger's logic-flaw labs): `-1` yields a negative total the flow happily "refunds", `0.5` breaks integer credit math, `2^31` overflows counters or reserves your entire inventory. Rule 4 fixed the *price*; this fixes everything multiplied by it.

```ts
// ❌ WRONG — client's quantity and total pass straight through
const { quantity, total } = await req.json();
await stripe.checkout.sessions.create({ line_items: [{ price: PRICES[plan], quantity }] });

// ✅ RIGHT — bounded integer quantity; server recomputes every derived number
const Order = z.strictObject({
  plan: z.enum(['starter', 'pro']),
  quantity: z.number().int().positive().max(MAX_QTY),   // e.g. 999
});
const { plan, quantity } = Order.parse(await req.json());
// subtotal/tax/discount/total computed HERE from the server-side price — any client
// copy is rejected by strictObject; currency is fixed by the Stripe Price ID (Rule 4),
// so no currency field exists in any inbound schema
```

```sql
-- ✅ mirror in the database (04 — Rule 8): holds against every future code path
alter table order_items add constraint qty_bounds check (quantity > 0 and quantity <= 999);
```

**Verify:** tests post quantity ∈ {-1, 0, 0.5, 2147483648} → all 400; a body carrying `total`/`subtotal`/`currency` → 400; direct insert with quantity 0 → constraint violation.

---

Previous: [10 — Headers, CSP & CORS](./10-headers-csp-cors.md) · See also: [08 — Webhooks](./08-webhooks.md) · Capstone: [15 — Self-Verification](./15-testing-verification.md)
