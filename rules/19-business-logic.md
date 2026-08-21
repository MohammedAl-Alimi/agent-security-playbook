# ⚖️ Business Logic & Workflow Integrity

The server owns every workflow: state transitions, derived numbers, and consume-once semantics are enforced in the database, because attackers replay, reorder, and parallelize requests your UI never sends.

## TL;DR — the rules

1. Model every multi-step flow as a server-side state machine: status enum + allowed-transition table, advanced in one transaction with a rowcount check.
2. Status fields are never client-settable; recompute all derived values (totals, discounts, scores, pass/fail) server-side and reject client copies.
3. Enforce one-shot semantics (trials, coupons, invites, votes) with DB UNIQUE constraints — never check-then-insert.
4. Coupons: no stacking by default, no discounts on stored-value products, Stripe `max_redemptions` + `first_time_transaction` set.
5. Referrals: pay out only after the referee's first paid invoice; deny self-referral; support clawback.
6. Block disposable emails and subaddress aliases at signup; normalize emails before entitlement checks; meter costly features per verified identity.
7. Inventory holds carry `expires_at` with automatic release, per-identity caps, and atomic hold→sale conversion on the payment webhook.
8. Feature flags are rollout tools, never authorization — flag-gated handlers still run server-side authz.

## Rule 1 — Every multi-step flow is a server-side state machine

CWE-841 (Improper Enforcement of Behavioral Workflow) and WSTG-BUSL-06 describe the class: checkout, KYC, approval, and fulfillment flows where each step is a separate endpoint and nothing verifies the caller arrived in order. ASVS V11.1.1 requires the app to "only process business logic flows in sequential step order". The fix is structural: a status enum, an explicit transition table, and an `UPDATE ... WHERE status = <expected>` whose rowcount is the guard — one statement that checks and advances atomically, so parallel requests can't both win (generalizes the race-safety patterns in [Payments](12-payments.md) and [Database & RLS](04-database-rls.md)).

```ts
// ❌ WRONG — TOCTOU: read, check, write; two parallel calls both pass the check.
// Also lets a caller ship an order that was never paid.
const order = await db.query.orders.findFirst({ where: eq(orders.id, id) });
if (order.status !== 'shipped') {
  await db.update(orders).set({ status: 'shipped' }).where(eq(orders.id, id));
}

// ✅ RIGHT — transition table + single guarded UPDATE; rowcount is the truth
const TRANSITIONS: Record<string, string[]> = {
  pending: ['paid', 'canceled'],
  paid: ['shipped', 'refunded'],
  shipped: ['delivered'],
};
export async function advance(id: string, from: string, to: string) {
  if (!TRANSITIONS[from]?.includes(to)) throw new Error(`illegal ${from}→${to}`);
  const res = await db.update(orders)
    .set({ status: to, statusChangedAt: sql`now()` })
    .where(and(eq(orders.id, id), eq(orders.status, from)));   // status guard IN the write
  if (res.rowCount !== 1) throw new ConflictError(`order ${id} not in '${from}'`);
}
```

Skipped-step attacks die here too: `ship` requires `from: 'paid'`, so a caller who never paid gets a 409 no matter which endpoint they hit first.

**Verify:** grep every `update(` touching a `status`/`state` column → each has a status predicate in its `WHERE` and checks rowcount; an integration test fires the same transition twice in parallel and asserts exactly one succeeds.

## Rule 2 — Derived values are recomputed server-side; status is never client-settable

PortSwigger's logic-flaws examples catalog the failure: prices, totals, and discounts accepted from the client, so `{"total": 0.01}` buys the cart. Extends [Input Validation](03-input-validation.md) Rule 3: inbound schemas simply have no field for `status`, `total`, `discount`, `score`, or `passed` — those are outputs of server computation over server-owned rows, never inputs.

```ts
// ❌ WRONG — client computed the total; quiz client decided it passed
await stripe.paymentIntents.create({ amount: body.total, currency: body.currency });
await db.update(attempts).set({ passed: body.passed }).where(eq(attempts.id, body.id));

// ✅ RIGHT — recompute from server-owned prices/answers; client sends only IDs
const items = await db.query.cartItems.findMany({ where: eq(cartItems.cartId, cartId) });
const amount = items.reduce((sum, i) => sum + i.unitPriceCents * i.qty, 0); // prices from DB
const score = grade(attempt.answers, await answerKeyFor(attempt.quizId));
await db.update(attempts)
  .set({ score, passed: score >= quiz.passThreshold })
  .where(eq(attempts.id, attempt.id));
```

**Verify:** grep inbound schemas for `total|price|amount|discount|status|score|passed` → zero hits without written justification; a fixture test posts a tampered total and asserts the charge uses the server-computed amount.

## Rule 3 — One-shot semantics via UNIQUE constraints, never check-then-insert

"Has this user already redeemed?" followed by an insert is a race: N parallel requests all read "no" and all insert. The OWASP Business Logic testing guide and [Payments](12-payments.md)'s parallel-request test generalize to every consume-once resource — trials, coupon redemptions, invite acceptances, votes, poll answers. The database is the only serialization point you actually have; make the constraint the control.

```sql
-- ✅ RIGHT — the constraint IS the business rule
CREATE TABLE coupon_redemptions (
  coupon_id  uuid NOT NULL REFERENCES coupons(id),
  user_id    uuid NOT NULL REFERENCES users(id),
  redeemed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (coupon_id, user_id)                      -- one redemption per user, enforced by Postgres
);
```

```ts
// ❌ WRONG — check-then-insert; 20 parallel requests redeem 20 times
const existing = await db.query.redemptions.findFirst({ where: ... });
if (!existing) await db.insert(redemptions).values({ couponId, userId });

// ✅ RIGHT — insert and let the constraint answer; 23505 = already redeemed
try {
  await db.insert(redemptions).values({ couponId, userId });
} catch (e) {
  if (isUniqueViolation(e)) throw new ConflictError('coupon already redeemed');
  throw e;
}
```

**Verify:** every consume-once table has a UNIQUE constraint expressing the rule (`\d+` in psql shows it); the ch12 parallel-race test runs against *every* consume-once endpoint — 20 concurrent redemptions yield exactly 1 row.

## Rule 4 — Coupon and referral economics are server rules, not UI hints

Promo abuse is a logic flaw with a P&L: stacking codes to negative totals, applying discounts to gift cards (buying stored value below face), and self-referral loops minting credit from nothing. Defaults: one coupon per order; coupons never apply to stored-value or credit products; use Stripe's native limits — `max_redemptions` on the promotion code and `restrictions.first_time_transaction` for new-customer-only offers — so the processor enforces what your code might miss. Referrals: reward only after the referee's **first paid invoice** (not signup — signups are free to fabricate), deny self-referral by identity (normalized email, payment fingerprint), and keep rewards revocable until the refund window closes so a charge-back claws the reward back.

```ts
// ❌ WRONG — unlimited redemptions, stacks with anything, rewards on signup
const promo = await stripe.promotionCodes.create({ coupon: coupon.id });
if (body.referrerId) await grantCredit(body.referrerId, 1000);   // client-supplied, instant

// ✅ RIGHT — Stripe-native limits; referral pays on invoice.paid, self-referral denied
const promo = await stripe.promotionCodes.create({
  coupon: coupon.id,
  max_redemptions: 500,
  restrictions: { first_time_transaction: true },
});
// webhook: invoice.paid (first invoice only)
const referral = await db.query.referrals.findFirst({ where: eq(referrals.refereeId, userId) });
if (referral && referral.referrerId !== userId &&
    normalizeEmail(referrer.email) !== normalizeEmail(referee.email)) {
  await grantCredit(referral.referrerId, 1000, { revocableUntil: refundDeadline(invoice) });
}
```

**Verify:** a test order with two coupons is rejected; a promotion code fixture asserts `max_redemptions` and `first_time_transaction` are set; a self-referral fixture (same normalized email) grants nothing.

## Rule 5 — Trial abuse: verified identity, not account count

OAT-019 (Account Creation) and OWASP API6:2023 (Unrestricted Access to Sensitive Business Flows) cover free-trial multi-accounting: `user+1@gmail.com` through `user+999@gmail.com` each get a fresh trial and fresh LLM credits. Three controls: (1) turn on your auth provider's one-toggle mitigations — Clerk ships disposable-email and subaddress blocking under Restrictions, and the community `disposable-email-domains` list covers self-hosted flows; (2) normalize emails (lowercase, strip `+tag`, collapse Gmail dots) *before* any entitlement check, and store the normalized form with a UNIQUE index (Rule 3); (3) meter costly features (LLM tokens, exports, sends) per **verified identity** — normalized verified email or payment fingerprint — never per account row.

```ts
// ❌ WRONG — trial keyed to account id; aliases mint infinite trials
if (!user.trialUsedAt) await startTrial(user.id);

// ✅ RIGHT — normalized identity + UNIQUE constraint owns the rule
export function normalizeEmail(raw: string): string {
  const [local, domain] = raw.trim().toLowerCase().split('@');
  const bare = local.split('+')[0];
  return `${['gmail.com', 'googlemail.com'].includes(domain) ? bare.replaceAll('.', '') : bare}@${domain}`;
}
await db.insert(trialGrants).values({ identity: normalizeEmail(user.email) });
// trial_grants.identity UNIQUE → second alias gets 23505, no trial
```

Rate-limit signup itself per IP/device (see [Rate Limiting](07-rate-limiting.md)) so farming is expensive even before the identity check.

**Verify:** Clerk dashboard (or config-as-code) shows disposable-email + subaddress blocking enabled; a fixture signs up `x+2@gmail.com` after `x@gmail.com` used the trial and asserts no second trial or credit grant.

## Rule 6 — Inventory holds expire; conversion to sale is atomic

OAT-021 (Denial of Inventory) and OAT-005 (Scalping): bots add stock to carts or book slots with no intent to pay, and your inventory hits zero for real customers. Every hold row carries `expires_at`; availability queries count only live holds; a sweep (cron or lazy, on read) releases expired ones. Cap concurrent holds per verified identity (Rule 5's identity, not account). Conversion happens on the payment webhook ([Webhooks](08-webhooks.md)) as one guarded UPDATE — a hold that expired before payment settles is a refund path, not an oversell.

```sql
-- ✅ RIGHT — holds are self-expiring; availability ignores dead holds
CREATE TABLE inventory_holds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sku_id uuid NOT NULL REFERENCES skus(id),
  identity text NOT NULL,
  qty int NOT NULL CHECK (qty > 0),
  status text NOT NULL DEFAULT 'held',            -- held | converted | released
  expires_at timestamptz NOT NULL                 -- e.g. now() + interval '10 minutes'
);
```

```ts
// ✅ RIGHT — atomic conversion: only a live hold converts (Rule 1's pattern)
const res = await db.update(holds)
  .set({ status: 'converted' })
  .where(and(eq(holds.id, holdId), eq(holds.status, 'held'), gt(holds.expiresAt, sql`now()`)));
if (res.rowCount !== 1) return refundAndApologize(paymentIntent);
```

**Verify:** an integration test creates a hold, advances past `expires_at`, and asserts the stock is sellable again; a per-identity cap test creating N+1 holds gets 429/409 on the last.

## Rule 7 — Feature flags are rollout tools, never authorization

Hidden is not protected: shipping the full flag ruleset to the browser reveals unreleased features and internal targeting rules, and a flag-gated UI without a server check is [Authorization](02-authorization.md)'s missing-authz bug wearing a flag costume. LaunchDarkly's own client-side guidance says client flags are visible to users — evaluate sensitive flags server-side and send only the booleans each page needs. And a flag check never *replaces* the authz check: flags answer "is this rolled out?", authz answers "may this caller do it?" — sensitive handlers require both, and flag evaluation fails closed.

```ts
// ❌ WRONG — the hidden button is the only gate; endpoint trusts the flag alone
export async function POST(req: Request) {
  if (!(await flags.enabled('bulk-export'))) return new Response(null, { status: 404 });
  return exportAllData();                        // any authenticated user, once flag is on
}

// ✅ RIGHT — flag gates rollout, authz gates access; both server-side
export async function POST(req: Request) {
  const { userId, orgId, role } = await auth();
  if (role !== 'admin') return new Response(null, { status: 403 });    // authz first, always
  if (!(await flags.enabled('bulk-export', { orgId }))) return new Response(null, { status: 404 });
  return exportOrgData(orgId);
}
```

**Verify:** grep for flag SDK bootstrap payloads in client bundles → only per-page booleans, never the ruleset; for every flag-gated mutation, a test flips the flag ON and calls it as a non-privileged user, asserting 403.

---

Next: [20 — OAuth, Federated Login & Account Lifecycle](./20-oauth-federated-login.md) (planned) · also see [02 — Authorization](./02-authorization.md), [12 — Payments](./12-payments.md)
