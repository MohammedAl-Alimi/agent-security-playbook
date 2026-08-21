# 🎫 OAuth, Federated Login & Account Lifecycle

Federated login fails at the seams — linking, redirects, and emailed links — not in the crypto. Treat every identity assertion as attacker-supplied until you have verified who signed it, who it was for, and which account it may touch.

## TL;DR — the rules

1. OAuth is Authorization Code + PKCE only; `state` is a CSPRNG value bound to the session and checked on callback.
2. Verify `id_token` `iss`, `aud`, `nonce`, and `exp` server-side; register exact-match redirect URIs, never wildcards.
3. Link accounts by immutable provider `sub`, never by email; auto-link only when both sides assert a verified email.
4. Every `returnTo`/`next`/`redirect_url` param is validated as a same-origin relative path against an allowlist.
5. Magic links: 32-byte CSPRNG token stored hashed, ≤15 min expiry, consumed via POST from a confirmation page — never on GET.
6. Regenerate the session ID on every privilege transition; revoke all other sessions on password change; enforce absolute + idle timeouts.
7. Passkeys: pin the RP ID explicitly; recovery paths get the same rigor as the passkey itself.
8. Never hand-roll SAML; delegate to Clerk Enterprise SSO/WorkOS with per-tenant IdP scoping.
9. Store provider tokens AES-GCM-encrypted with minimum scopes; revoke at the provider on disconnect.

## Rule 1 — Authorization Code + PKCE, CSPRNG state bound to the session

**Why:** RFC 9700 (OAuth 2.0 Security Best Current Practice) deprecates the implicit grant and requires PKCE for all clients: the code verifier stops injected authorization codes, and `state` stops login CSRF. next-auth CVE-2022-24858 showed what a weak callback check costs in this exact stack. Managed SDKs (Clerk, `@supabase/ssr`) do this for you — the rule exists so you never hand-roll a flow beside them.

```ts
// ❌ WRONG — implicit flow, no PKCE, guessable state
const url = `${AUTH}/authorize?response_type=token&client_id=${ID}&state=login`;

// ✅ RIGHT — code + PKCE; state/verifier generated per-request, bound to session
import { randomBytes, createHash } from 'crypto';
const state = randomBytes(32).toString('base64url');
const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
cookies().set('__Host-oauth', JSON.stringify({ state, verifier }), {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 600,
});
const url = `${AUTH}/authorize?response_type=code&client_id=${ID}` +
  `&code_challenge=${challenge}&code_challenge_method=S256&state=${state}` +
  `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
// callback: reject unless req state === cookie state, then exchange code + verifier
```

**Verify:** grep for `response_type=token` and any `/authorize` URL built without `code_challenge` → zero; test replays a callback with a mismatched `state` → rejected, no session created.

## Rule 2 — Verify the id_token; register exact redirect URIs

**Why:** An `id_token` you don't validate is just attacker-controlled JSON. RFC 9700 and the OpenID Connect Core spec require checking `iss` (right provider), `aud` (issued to *your* client, not any app the attacker registered), `nonce` (bound to this login), and `exp`. Wildcard or path-prefix redirect URIs let attackers receive your authorization codes — Supabase's redirect-URL docs exist precisely because glob patterns get this wrong.

```ts
// ❌ WRONG — decode without verify; wildcard redirect registered at provider
const claims = JSON.parse(atob(idToken.split('.')[1])); // trusts anything
// Provider config: redirect_uri = https://app.example.com/*

// ✅ RIGHT — full verification against provider JWKS; exact redirect URI
import { jwtVerify, createRemoteJWKSet } from 'jose';
const jwks = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));
const { payload } = await jwtVerify(idToken, jwks, {
  issuer: ISSUER, audience: CLIENT_ID, // iss + aud enforced
});
if (payload.nonce !== expectedNonce) throw new Error('nonce mismatch');
// Provider config: exactly https://app.example.com/api/auth/callback — no *, no trailing paths
```

Keep callback pages free of third-party scripts/assets, and strip `code`/`state` from the URL (`history.replaceState`) immediately — Referer headers leak them.

**Verify:** test feeds the callback an id_token signed by another tenant/audience → rejected; provider dashboard lists only exact-match redirect URIs (no `*`).

## Rule 3 — Link by immutable `sub`, never by email

**Why:** The nOAuth class: providers can assert unverified or attacker-changeable emails, so "find user by email and log them in" merges an attacker's OAuth identity into a victim's account. Better Auth CVE-2026-53516 (GHSA-g38m-r43w-p2q7) and Authorizer CVE-2026-35511 are 2026 instances of the same pre-account-takeover bug: register the victim's email unverified (or via a lax provider), wait for the victim to OAuth in, inherit their account. The provider `(iss, sub)` pair is the only stable identity.

```ts
// ❌ WRONG — email is the join key; unverified rows merge silently
const user = await db.user.findUnique({ where: { email: profile.email } });
if (user) return createSession(user.id); // attacker's pre-registered row wins

// ✅ RIGHT — sub is the key; email-match only links when BOTH sides are verified
const account = await db.account.findUnique({
  where: { provider_sub: { provider: 'google', sub: profile.sub } },
});
if (account) return createSession(account.userId);
const existing = await db.user.findUnique({ where: { email: profile.email } });
if (existing) {
  if (!profile.email_verified || !existing.emailVerified) {
    return redirect('/sign-in?error=link_requires_login'); // fresh re-auth, no auto-merge
  }
  await db.account.create({ data: { userId: existing.id, provider: 'google', sub: profile.sub } });
  return createSession(existing.id);
}
// else: create a brand-new user
```

**Verify:** self-verification test — register `victim@example.com` with a password, leave it unverified, then complete an OAuth login asserting the same email → two separate accounts (or a re-auth challenge), never a merge; grep account-linking code for `findUnique({ where: { email` used as the primary lookup → zero.

## Rule 4 — Validate every returnTo/next redirect param

**Why:** An open redirect on your own auth pages turns your domain into a phishing launcher and, chained with OAuth, can leak authorization codes to attacker origins (OWASP Unvalidated Redirects cheat sheet). `startsWith('/')` alone fails: `//evil.com` and `/\evil.com` are protocol-relative in browsers.

```ts
// ❌ WRONG — redirect(req.query.next) in any spelling
return NextResponse.redirect(searchParams.get('returnTo') ?? '/dashboard');

// ✅ RIGHT — same-origin relative path or a fixed fallback
function safeReturnTo(raw: string | null): string {
  if (!raw) return '/dashboard';
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return '/dashboard';
  const url = new URL(raw, 'https://app.example.com');
  return url.origin === 'https://app.example.com' ? url.pathname + url.search : '/dashboard';
}
return NextResponse.redirect(new URL(safeReturnTo(searchParams.get('returnTo')), req.url));
```

**Verify:** grep for `redirect(` fed by `searchParams`/`req.query` without the validator → zero; test `?returnTo=//evil.com`, `?returnTo=https://evil.com`, `?returnTo=/\evil.com` → all land on `/dashboard`.

## Rule 5 — Magic links: hashed token, short expiry, POST-consumed

**Why:** Corporate mail scanners (Microsoft Defender SafeLinks, Mimecast) prefetch every emailed URL — a GET-consumed magic link is burned (or worse, *logs the scanner in*) before the human clicks. And a plaintext token in the DB means a DB read replays every pending login. Same design as password-reset tokens in [hashing & tokens](06-hashing-and-tokens.md); OWASP's Forgot Password cheat sheet applies verbatim.

```ts
// ❌ WRONG — plaintext token, long-lived, session created on GET
// GET /auth/magic?token=abc → createSession()  ← the scanner just logged in

// ✅ RIGHT — hashed at rest, ≤15 min, GET renders a page, POST consumes atomically
const token = randomBytes(32).toString('base64url');
await db.magicLink.create({ data: {
  tokenHash: createHash('sha256').update(token).digest('hex'),
  userId, expiresAt: new Date(Date.now() + 15 * 60_000),
}});
// email contains /auth/confirm?token=... ; that page is static + a <form method="post">
// POST handler: single atomic consume — no check-then-delete race
const { count } = await db.magicLink.deleteMany({
  where: { tokenHash: hash(token), expiresAt: { gt: new Date() } },
});
if (count !== 1) return new Response('Invalid or expired link', { status: 400 });
```

Offer an OTP-code fallback for enterprise recipients whose gateways rewrite links. Rate-limit issuance per email ([rate limiting](07-rate-limiting.md)).

**Verify:** test GETs the confirmation URL 5× → token still valid, no session; then POSTs once → session; POSTs again → 400. Grep for magic/reset token columns stored without hashing → zero.

## Rule 6 — Session lifecycle: rotate, revoke, expire

**Why:** Session fixation: a session ID that survives login lets an attacker who planted it pre-auth ride it post-auth (OWASP Session Management cheat sheet). A stolen password that gets changed but leaves old sessions alive changes nothing for the attacker already inside. Extends [authentication](01-authentication.md) Rule 4.

```ts
// ❌ WRONG — same session ID before and after login; password change keeps sessions
await db.user.update({ where: { id }, data: { passwordHash: newHash } }); // done?

// ✅ RIGHT — rotate on privilege transitions, revoke-all on credential change
await createSession(userId, { rotateFrom: currentSessionId }); // new ID at login/step-up
await db.$transaction([
  db.user.update({ where: { id: userId }, data: { passwordHash: newHash } }),
  db.session.deleteMany({ where: { userId, id: { not: currentSessionId } } }),
]);
// every session row: absoluteExpiry (e.g. 30d) AND lastSeenAt idle check (e.g. 24h)
```

Clerk and Supabase Auth rotate and support revoke-all natively (`sessions.revokeSession`, `auth.admin.signOut(userId, 'others')`) — wire the password-change hook to actually call it.

**Verify:** [testing](15-testing-verification.md) captures the session cookie pre-login and asserts it differs post-login; test changes the password in session A → session B's next request is 401.

## Rule 7 — Passkeys: pin the RP ID, harden recovery

**Why:** A WebAuthn RP ID derived from the Host header lets a spoofed host bind credentials to the wrong relying party — pin it to your registrable domain in config. And a phishing-resistant passkey guarded by a phishable fallback (email link, SMS reset) is only as strong as the fallback: attackers go through recovery, not the passkey (Microsoft Entra's "passkeys aren't the finish line" guidance).

```ts
// ❌ WRONG — RP ID from the request; recovery = plain email link
const rpID = new URL(req.url).hostname;

// ✅ RIGHT — constant RP ID; recovery demands equivalent assurance
const rpID = 'example.com'; // registrable domain, from config, never the Host header
// recovery: existing second factor, or identity re-verification + delay + notify-all-channels
```

Prefer Clerk/Supabase passkey implementations over hand-rolling `navigator.credentials` ceremonies.

**Verify:** grep WebAuthn config for `req.headers.host`/`url.hostname` feeding `rpID` → zero; walk the recovery path in a test — it must require a factor at least as strong as a password + verified channel, never a bare emailed GET link (Rule 5).

## Rule 8 — SAML is never hand-rolled

**Why:** SAML signature verification keeps falling to parser differentials — two XML parsers disagreeing about which bytes were signed. ruby-saml CVE-2025-25291/25292 (GitHub's "sign in as anyone" write-up) and CVE-2025-66567/66568 are the same class years apart; hand-rolled or thinly-wrapped XML verification is a standing liability. Buy, don't build: Clerk Enterprise SSO or WorkOS terminate SAML for you.

```ts
// ❌ WRONG — DIY assertion parsing, one IdP cert trusted for every tenant
const doc = new DOMParser().parseFromString(samlResponse); // parser differential territory

// ✅ RIGHT — delegated, and each connection is scoped to ONE tenant
const { userId, orgId } = await auth();               // Clerk handled the SAML leg
if (conn.orgId !== invitedOrgId) throw new Error(...); // tenant A's IdP can never mint tenant B users
```

**Verify:** grep dependencies for `xml-crypto`/`saml` libraries imported by first-party code → zero (only the managed provider touches SAML); test that an assertion from tenant A's IdP cannot create or access a session in tenant B.

## Rule 9 — Provider tokens: encrypt, minimize, revoke

**Why:** OAuth access/refresh tokens for connected providers (Google, GitHub) are live credentials to the user's external data — a DB leak becomes a cross-service breach. Store them AES-256-GCM encrypted ([hashing & tokens](06-hashing-and-tokens.md)), request the minimum scopes the feature needs, and on disconnect revoke at the provider — deleting your row does not invalidate the token, and [client data protection](17-client-data-protection.md) DSR deletion must include it.

```ts
// ❌ WRONG — plaintext token, broad scope, "disconnect" = DELETE row
scopes: ['https://www.googleapis.com/auth/gmail.modify'] // to read one label

// ✅ RIGHT — minimal scope, encrypted at rest, revoked upstream on disconnect
scopes: ['https://www.googleapis.com/auth/gmail.readonly'];
await db.connection.create({ data: { userId, encToken: aesGcmEncrypt(token, KEY) } });
// disconnect:
await fetch('https://oauth2.googleapis.com/revoke', {
  method: 'POST', body: new URLSearchParams({ token }),
});
await db.connection.delete({ where: { id } });
```

**Verify:** grep the schema for provider token columns without the encryption wrapper → zero; disconnect a test connection, then call the provider API with the old token → provider returns invalid-token.
