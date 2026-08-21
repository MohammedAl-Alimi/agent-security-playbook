# ✉️ Email, SMS & Notifications

Email and SMS are auth infrastructure: they carry the links and codes that reset passwords and change identities. Secure the channel (DMARC), the message (injection), and the flows riding on it (address changes, OTP, unsubscribe).

## TL;DR — the rules

1. Send from a dedicated subdomain with SPF + DKIM aligned and DMARC ramped `p=none` → `quarantine` → `reject` with reporting; `dig` the records pre-launch.
2. Reject `\r`/`\n` in every header-bound field at the schema, use SDK structured fields only, HTML-escape every interpolated value, and load recipients from the DB — never the request body.
3. Email/phone change is account takeover: fresh re-auth, switch only after the NEW address confirms, notify the OLD address with a revert link, invalidate old-address reset tokens.
4. SMS/OTP: 3–5 verify attempts then invalidate, constant-time compare, per-phone cooldowns, destination-country allowlist; SMS is never the sole factor for credential changes.
5. Marketing mail carries RFC 8058 one-click unsubscribe with a per-recipient HMAC token, consumed POST-only; security notifications are never suppressible.

## Rule 1 — Authenticated sending domain with an enforcing DMARC ramp

**Why:** Gmail and Yahoo bulk-sender requirements make SPF/DKIM plus a DMARC policy a delivery precondition, and a `p=none`-forever domain lets anyone spoof `security@yourapp.com` — the exact From line a phisher wants for fake reset emails. A dedicated subdomain (`send.example.com` in Resend) isolates transactional reputation from the root domain and from marketing blasts; DKIM alignment is what actually binds the signature to your From domain under DMARC.

```ts
// ❌ WRONG — sending from the bare root with no DMARC record
await resend.emails.send({ from: 'noreply@example.com', ... }); // _dmarc.example.com: NXDOMAIN

// ✅ RIGHT — verified subdomain; DMARC ramped as reports come back clean
// DNS (via Resend domain verification for send.example.com):
//   TXT send.example.com          "v=spf1 include:amazonses.com ~all"
//   TXT resend._domainkey.send... "p=MIGfMA0GCSq..."   ← DKIM, d= aligns with From
//   TXT _dmarc.example.com        "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
//   → after 2–4 weeks of clean rua reports: p=quarantine → p=reject
await resend.emails.send({ from: 'Acme <login@send.example.com>', ... });
```

Keep marketing and transactional on separate streams (different subdomains or providers) so a spam-complaint spike never blocks password resets.

**Verify:** pre-launch CI/checklist step runs `dig TXT _dmarc.example.com +short` (non-empty, policy present) and `dig TXT resend._domainkey.send.example.com +short`; a mail sent to a Gmail test account shows `spf=pass`, `dkim=pass`, `dmarc=pass` in the *Show original* headers.

## Rule 2 — No user input reaches headers or unescaped HTML

**Why:** CRLF in a header-bound field splits the message — injected `Bcc:`/`Cc:` headers turn your sender into a spam relay (nodemailer GHSA-268h-hp4c-crq3; WSTG SMTP-injection testing). Unescaped interpolation into HTML bodies is stored XSS delivered by your own trusted domain (Papra GHSA-6f8x-2rc9-vgh4: attacker HTML in invitation emails). And a recipient list taken from the request body lets any caller aim your templates at anyone.

```ts
// ❌ WRONG — user strings straight into subject/HTML; recipients from the client
await resend.emails.send({
  to: body.to,                                        // caller-controlled targets
  subject: `${body.name} invited you`,                // \r\nBcc: victims@...
  html: `<p>Message from ${body.name}: ${body.note}</p>`, // <script> lands here
});

// ✅ RIGHT — schema rejects CRLF, values escaped, recipients resolved server-side
const InviteInput = z.object({
  name: z.string().max(80).refine(v => !/[\r\n]/.test(v), 'no line breaks'),
  note: z.string().max(500),
  inviteeId: z.uuid(),
});
const esc = (s: string) =>
  s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const invitee = await db.user.findUniqueOrThrow({ where: { id: input.inviteeId } });
await resend.emails.send({
  to: invitee.email,                                   // from DB, not the request
  subject: `${input.name} invited you`,                // structured field, CRLF-free
  html: `<p>Message from ${esc(input.name)}: ${esc(input.note)}</p>`,
});
```

SDK structured fields (`to`, `subject`, `headers`) only — never concatenate raw MIME. A Semgrep rule flags template-literal `html:` values near `resend.emails.send` that interpolate identifiers without the escaper.

**Verify:** Semgrep rule in CI → zero unescaped interpolations; test posts `name: "x\r\nBcc: evil@example.com"` → 400 at validation, no send; grep for `to:` fed from `req`/`body`/`parsedInput` fields that aren't DB lookups → zero.

## Rule 3 — Email/phone change is an account-takeover flow

**Why:** Whoever controls the account email controls password reset — so "change email" is the takeover primitive, and it's the flow attackers run *after* stealing a session (GitLab's own tracker documents the notify-old requirement). Supabase ships `double_confirm_changes` for exactly this, but `mailer_autoconfirm: true` silently bypasses the new-address confirmation (supabase/auth #2600) — the config pair must be verified end-to-end, not assumed.

```ts
// ❌ WRONG — one authenticated request flips the identity instantly
await db.user.update({ where: { id: userId }, data: { email: input.newEmail } });

// ✅ RIGHT — re-auth, confirm on NEW, switch, then notify OLD with a revert path
if (!(await verifyRecentAuth(session, { maxAgeMinutes: 5 }))) // password/passkey, not SMS (Rule 4)
  return { error: 'reauth_required' };
await sendConfirmation(input.newEmail, pendingChangeToken);    // hashed, ≤15 min — see ch20 Rule 5
// on POST-confirm from the NEW address, in one transaction:
//   1. swap user.email; 2. invalidate ALL reset/magic tokens issued to the OLD address;
//   3. revoke other sessions (ch20 Rule 6)
await sendToOldAddress(oldEmail, {
  subject: 'Your account email was changed',
  revertUrl: signedRevertLink(userId, oldEmail, { ttlDays: 7 }), // freezes account + restores
});
```

Supabase config: `double_confirm_changes: true` **and** `mailer_autoconfirm: false` — then prove it with a test, since the second flag silently defeats the first. Phone changes follow the identical shape.

**Verify:** E2E test changes the email, then requests a password reset for the OLD address → no usable token; asserts the OLD address received the notification with a working revert link; asserts a change attempt without fresh re-auth → `reauth_required`.

## Rule 4 — SMS/OTP: throttle, compare constant-time, block pumping

**Why:** A 6-digit OTP with unlimited tries falls to ~1M guesses of brute force — cap attempts, then invalidate. NIST SP 800-63B classifies SMS (PSTN) as a *restricted* factor because of SIM-swap, so it must never be the only gate on email/password changes (Rule 3). And SMS-pumping fraud (Twilio's toll-fraud guidance) turns an open "send code" endpoint into an attacker revenue stream dialing premium-rate ranges — burn rate shows up on your invoice, not your dashboard.

```ts
// ❌ WRONG — unlimited attempts, ===, any country, SMS authorizes email change
if (input.code === row.code) approveEmailChange();

// ✅ RIGHT — capped, constant-time, cooled down, geo-fenced
import { timingSafeEqual } from 'crypto';
const ALLOWED_COUNTRIES = new Set(['DE', 'US', 'GB']);      // where your users actually are
if (!ALLOWED_COUNTRIES.has(lookupCountry(phone))) return deny('unsupported_region');
await enforceCooldown(`otp:send:${phone}`, { perMinute: 1, perDay: 5 }); // ch07 limiter
// verify:
const row = await db.otp.findFirst({ where: { phone, expiresAt: { gt: new Date() } } });
if (!row || row.attempts >= 5) { await db.otp.deleteMany({ where: { phone } }); return deny(); }
await db.otp.update({ where: { id: row.id }, data: { attempts: { increment: 1 } } });
const ok = timingSafeEqual(Buffer.from(hash(input.code)), Buffer.from(row.codeHash));
```

Add a line-type lookup (reject VoIP/premium ranges) via your SMS provider before sending. SMS may *add* assurance; it never solely authorizes a credential or contact-detail change.

**Verify:** test submits 6 wrong codes → OTP invalidated, correct code now rejected; test hammers send-code → cooldown 429s after the cap ([rate limiting](07-rate-limiting.md)); grep credential-change handlers for acceptance paths where SMS is the only verified factor → zero.

## Rule 5 — RFC 8058 one-click unsubscribe, HMAC-scoped and POST-only

**Why:** Gmail/Yahoo require one-click unsubscribe (RFC 8058) on bulk mail. Get the token wrong and you've built a mass-unsubscribe oracle: a raw user ID or email in the URL lets anyone unsubscribe anyone by iterating IDs. And RFC 8058 is explicitly a POST contract — a GET that unsubscribes is executed by every corporate link scanner (same prefetch failure as magic links, [OAuth & account lifecycle](20-oauth-account-lifecycle.md) Rule 5).

```ts
// ❌ WRONG — guessable, GET-actioned, unsubscribes from everything
// List-Unsubscribe: <https://example.com/unsub?user=123>   ← scanner + enumeration

// ✅ RIGHT — per-recipient, list-scoped HMAC; POST performs, GET only confirms
import { createHmac } from 'crypto';
const token = createHmac('sha256', env.UNSUB_SECRET)
  .update(`${userId}:${listId}`).digest('base64url');
headers: {
  'List-Unsubscribe': `<https://example.com/api/unsub?u=${userId}&l=${listId}&t=${token}>`,
  'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',   // RFC 8058: mail client POSTs
}
// POST /api/unsub: recompute HMAC (timingSafeEqual), unsubscribe from listId ONLY
// GET  /api/unsub: render a confirmation page with a <form method="post"> — no state change
```

Tokens are list-scoped: unsubscribing from `newsletter` never touches other lists — and security notifications (password changed, new login, email changed — Rule 3) live outside the preference system entirely and are never suppressible.

**Verify:** test GETs the unsubscribe URL → subscription unchanged; POST with a tampered token → 400; POST with a valid token → only that list flipped; grep notification-send paths for security events routed through the preference check → zero.
