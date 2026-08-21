# 🔒 Hashing, Tokens & Credentials

Every credential is either hashed, encrypted, or a breach waiting for a database dump. Know which primitive applies, generate secrets from a CSPRNG, and compare them in constant time.

## TL;DR — the rules

1. Hash passwords server-side with Argon2id (m=19456 KiB, t=2, p=1) or bcrypt (cost ≥ 10); never MD5/SHA-x/plaintext, never client-side-only.
2. Generate every token with `crypto.randomBytes(32)` / `secrets.token_urlsafe(32)` — never `Math.random()`.
3. Store only hashes of long-lived secrets: API keys, reset/verification tokens, refresh tokens — single-use, short TTL.
4. Compare secrets and signatures with `crypto.timingSafeEqual` / `hmac.compare_digest`, never `===`.
5. JWTs: vetted lib, pinned algorithm allowlist, ≤15-min access tokens, verify `aud`/`iss`/`exp`, no secrets or PII in the payload.
6. Prefer revocable server-side sessions over JWTs for user auth; either way the token rides an httpOnly cookie.
7. Encrypt (don't hash) data you must read back: AES-256-GCM, unique IV per encryption, key from env/KMS.
8. Rehash on login whenever stored params are below current policy.
9. Supabase JWTs: verify against the project JWKS with an RS256/ES256 allowlist — never a copied shared secret; rotate via standby keys.

## Rule 1 — Argon2id (or bcrypt) server-side; nothing else

**Why:** GPUs compute billions of MD5/SHA-256 guesses per second; memory-hard Argon2id is the OWASP Password Storage Cheat Sheet default (minimum: **m=19456 KiB, t=2, p=1**), with bcrypt (work factor ≥ 10) the legacy-compatible fallback. Both embed a random per-password salt in the output string — hand-rolled salting or `sha256(salt + pw)` schemes are strictly worse; never build them. Hash on the **server**: a client-side-only hash just turns the hash into the password (pass-the-hash). The only starter in the survey doing this right is full-stack-fastapi-template (pwdlib, Argon2 + bcrypt fallback with rehash-on-verify) — copy it.

```ts
// ❌ WRONG — fast hash, hand-rolled salt, or client-side "hashing"
import { createHash } from 'crypto';
const hash = createHash('sha256').update(salt + password).digest('hex');

// ✅ RIGHT — argon2id with OWASP params; salt handled internally
import argon2 from 'argon2';
const hash = await argon2.hash(password, {
  type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1,
});
const ok = await argon2.verify(hash, password);
```

```python
# ✅ Python — pwdlib (the full-stack-fastapi-template pattern)
from pwdlib import PasswordHash
pwd = PasswordHash.recommended()      # Argon2id
hash_ = pwd.hash(password)
ok, new_hash = pwd.verify_and_update(password, stored_hash)  # rehash hook, see Rule 8
```

bcrypt caveat: it silently truncates input at **72 bytes** — enforce a password max length (e.g. 64 chars) or prefer Argon2id. Optional **pepper**: HMAC the password with a key from env/KMS *before* hashing so a pure DB dump is uncrackable — the pepper never lives in the database.

**Verify:** grep server code for `md5|sha1|sha256` within password/credential paths → zero; unit test asserts stored value starts with `$argon2id$` (or `$2b$` with cost ≥ 10) and that two hashes of the same password differ (salt present).

## Rule 2 — Tokens come from a CSPRNG, never `Math.random()`

**Why:** `Math.random()` is a predictable PRNG — observing a few outputs lets an attacker reconstruct the state and forge "random" reset tokens, invite codes, and API keys. AI-generated code reaches for it constantly because it looks sufficient in the happy path (the omission failure mode: Veracode 2025 measured AI introducing vulnerabilities in 45% of tasks). Minimum secret entropy: 256 bits (32 bytes).

```ts
// ❌ WRONG — predictable, enumerable
const token = Math.random().toString(36).slice(2);

// ✅ RIGHT — 32 bytes from the OS CSPRNG, URL-safe
import { randomBytes } from 'crypto';
const token = randomBytes(32).toString('base64url');
```

```python
# ✅ Python
import secrets
token = secrets.token_urlsafe(32)   # random module is the Math.random() of Python — never for secrets
```

`crypto.randomUUID()` is acceptable for identifiers (122 random bits) but prefer 32 bytes for bearer secrets.

**Verify:** grep for `Math.random`/`random.random`/`random.choice` in any file that mints tokens, keys, codes, or IDs used for auth → zero hits; CI Semgrep rule keeps it that way.

## Rule 3 — Store only hashes of long-lived secrets

**Why:** A bearer token stored in plaintext makes every DB dump, log leak, and backup a full account takeover — the same reason we hash passwords. Unlike passwords, these tokens are high-entropy (Rule 2), so a **single fast SHA-256 is correct and sufficient** here; Argon2's slowness would only tax your own lookups. This applies to API keys, password-reset tokens, email-verification tokens, and refresh tokens.

```ts
// ❌ WRONG — plaintext bearer secrets at rest
await db.apiKey.create({ data: { userId, key } });

// ✅ RIGHT — show plaintext once; persist only the SHA-256
import { createHash, randomBytes } from 'crypto';
const secret = randomBytes(32).toString('base64url');
const key = `sk_live_${secret}`;                    // recognizable prefix → secret scanners catch leaks
await db.apiKey.create({ data: {
  userId,
  keyHash: createHash('sha256').update(key).digest('hex'),
  keyPrefix: key.slice(0, 16),                      // 'sk_live_' + first chars, plaintext, for lookup/display
}});
return key; // displayed exactly once, never retrievable again

// verify an incoming key: hash it, look up by hash (or by prefix, then timing-safe compare — Rule 4)
```

Reset/verification tokens additionally: **short TTL** (reset ≤ 1h, verification ≤ 24h), **single-use** (delete the row inside the same transaction that consumes it), and **invalidate all outstanding reset tokens + refresh tokens on password change**. The email link carries the plaintext; the DB never does.

**Verify:** pick any secret-bearing table and assert column values are 64-char hex (SHA-256), not `sk_`/token-shaped plaintext; test consumes a reset token twice → second attempt 400; test changes password → prior reset token and refresh tokens all rejected.

## Rule 4 — Timing-safe comparison for every secret

**Why:** `a === b` (and SQL `WHERE token = $1` on a *plaintext* column) short-circuits at the first differing byte — attackers recover secrets byte-by-byte from response-time deltas. Any comparison whose operands include a secret (API key, HMAC/webhook signature, token, OTP) must be constant-time. (Looking up by *hash* as in Rule 3 also defuses this, since the attacker can't control hash bytes.)

```ts
// ❌ WRONG — early-exit comparison leaks matching prefix length
if (signature === expectedSignature) { ... }

// ✅ RIGHT — constant-time, length-checked
import { timingSafeEqual } from 'crypto';
const a = Buffer.from(signature), b = Buffer.from(expectedSignature);
const ok = a.length === b.length && timingSafeEqual(a, b);
```

```python
# ✅ Python
import hmac
ok = hmac.compare_digest(signature, expected_signature)
```

Webhook SDK verifiers (`stripe.webhooks.constructEvent`, Clerk/svix `verifyWebhook`) already do this — use them instead of hand-rolling HMAC checks.

**Verify:** grep for `==`/`===` where either operand is named like `token|signature|secret|apiKey|otp|digest` → zero; code review gate via a repo-local Semgrep rule.

## Rule 5 — JWT discipline: allowlist algorithms, short expiry, verified claims

**Why:** The classic JWT breaks are library-level: accepting `alg: none` (signature stripped), and algorithm-confusion — sending HS256 signed with the *public* RS256 key when the verifier accepts both. The fix is structural: a vetted library (`jose` in Node — the research corpus's blessed pick; `PyJWT` in Python) with the accepted algorithm list pinned by **you**, never read from the token header.

```ts
// ❌ WRONG — decode ≠ verify; no algorithm pin; secrets in payload
const claims = jwt.decode(token) as Claims;            // NO verification at all
jwt.verify(token, key);                                 // alg taken from attacker's header

// ✅ RIGHT — jose with algorithm + issuer + audience pinned
import { jwtVerify } from 'jose';
const { payload } = await jwtVerify(token, secretKey, {
  algorithms: ['HS256'],            // exactly what you issue — reject everything else
  issuer: 'https://myapp.example',
  audience: 'myapp-api',
  clockTolerance: 5,
});
```

Rules: access tokens expire in **≤ 15 minutes**; refresh tokens are opaque CSPRNG values stored hashed (Rule 3) and **rotated on every use — a reused (already-rotated) refresh token means theft: revoke the whole token family**. Always verify `exp`, `iss`, `aud`. The payload is base64, not encryption — no secrets, no PII beyond an opaque subject ID. Symmetric signing secrets: ≥ 256 bits from env/KMS, never hardcoded, never an English phrase.

**Verify:** tests feed the API (a) an `alg:none` token, (b) an HS256 token when RS256 is expected, (c) an expired token, (d) a wrong-`aud` token → all 401; grep for `jwt.decode(`/`decodeJwt(` used for auth decisions → zero.

## Rule 6 — Sessions vs JWTs: default to revocable sessions

**Why:** A stateless JWT cannot be revoked before `exp` — logout, password change, and account compromise all leave a live credential in the wild. Server-side sessions (opaque CSPRNG ID → session row, or the managed session your auth provider runs) revoke instantly and leak nothing in the token. Choose JWTs only for service-to-service calls or when a managed provider (Clerk, Supabase Auth) pairs short-lived JWTs with its own revocation/refresh machinery.

```ts
// ❌ WRONG — self-rolled "stateless auth": 7-day JWT in localStorage
const token = jwt.sign({ userId, role }, SECRET, { expiresIn: '7d' });

// ✅ RIGHT — opaque session token, hashed at rest, revocable, httpOnly cookie
const sessionToken = randomBytes(32).toString('base64url');
await db.session.create({ data: {
  tokenHash: sha256(sessionToken), userId, expiresAt: hours(24),
}});
cookies().set('__Host-session', sessionToken, {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/',
});
```

Either way, storage is an httpOnly cookie — see [authentication](01-authentication.md) Rule 4. Note the `role` claim above: authorization data belongs to the server lookup, not a client-held token that outlives a demotion ([authorization](02-authorization.md)).

**Verify:** test logs out (or changes password), then replays the old cookie/token → 401; if using JWTs, document the revocation path (short expiry + refresh rotation) in the repo and test it.

## Rule 7 — Encryption ≠ hashing: AES-256-GCM for data you must read back

**Why:** Hashing is one-way (passwords, tokens you only ever *verify*). Data you must retrieve — OAuth access tokens for third-party APIs, TOTP secrets, government IDs — needs authenticated **encryption**. AI code notoriously picks the wrong primitive (base64 "encryption", or hashing a value later needed in plaintext). Use AES-256-GCM: authenticated, standard, in every stdlib. The catastrophic footgun is IV reuse — a repeated IV under the same GCM key breaks confidentiality *and* authenticity, so generate a fresh random 12-byte IV per encryption and store it beside the ciphertext.

```ts
// ❌ WRONG — base64 is encoding, not encryption (and a static IV breaks GCM)
const encrypted = Buffer.from(secret).toString('base64');

// ✅ RIGHT — AES-256-GCM, fresh IV each time, key from env/KMS (never the repo)
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
const key = Buffer.from(process.env.FIELD_ENCRYPTION_KEY!, 'base64'); // 32 bytes, generated by CSPRNG
export function encrypt(plaintext: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv, ct, tag: cipher.getAuthTag() };   // persist all three
}
```

Key management: 256-bit key from env (validated at boot — see the secrets chapter) or a KMS; plan key rotation via a `key_version` column. Python: `cryptography`'s `AESGCM` — same shape.

**Verify:** unit test encrypts the same plaintext twice → different ciphertexts (fresh IVs); tampering one ciphertext byte → decrypt throws; grep for `createCipheriv` calls with a literal/static IV → zero.

## Rule 8 — Rehash on login when params are outdated

**Why:** Hash parameters that were fine in 2020 are weak now, and old rows keep old params forever unless upgraded. Login is the only moment you hold the plaintext — verify against the stored hash, and if its algorithm or cost is below current policy, rehash and overwrite in place. full-stack-fastapi-template ships exactly this via pwdlib's `verify_and_update`.

```ts
// ❌ WRONG — verify only; bcrypt-cost-8 rows from 2019 live forever
const ok = await argon2.verify(user.passwordHash, password);

// ✅ RIGHT — verify, then upgrade stale hashes while the plaintext is in hand
const ok = await verifyAny(user.passwordHash, password); // handles legacy bcrypt too
if (ok && argon2.needsRehash(user.passwordHash, CURRENT_PARAMS)) {
  await db.user.update({ where: { id: user.id },
    data: { passwordHash: await argon2.hash(password, CURRENT_PARAMS) } });
}
```

Python: `ok, new_hash = pwd.verify_and_update(password, stored)` — persist `new_hash` when non-null.

**Verify:** test seeds a user with a legacy hash (e.g. bcrypt cost 8), logs in successfully → stored hash now matches current policy (`$argon2id$` with current params) and login still works on the second attempt.

## Rule 9 — Supabase asymmetric JWT keys: verify via JWKS, never a copied secret

**Why:** Since October 2025, new Supabase projects sign JWTs with asymmetric keys (RS256/ES256) by default. The legacy pattern — pasting the shared HS256 JWT secret into every backend that verifies tokens — made each of those services a signing oracle: leak any one env file and the attacker forges tokens for the whole project. With asymmetric keys, services verify against the public JWKS and hold no signing material at all.

```python
# ❌ WRONG — shared secret copied into a second service; algorithm not pinned
payload = jwt.decode(token, SUPABASE_JWT_SECRET)

# ✅ RIGHT — FastAPI verifies against the project JWKS, algorithms pinned by you (Rule 5)
from jwt import PyJWKClient
jwks = PyJWKClient("https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json")
key = jwks.get_signing_key_from_jwt(token)
payload = jwt.decode(token, key.key, algorithms=["ES256", "RS256"],  # allowlist, never header
                     audience="authenticated")
```

Node: `jose`'s `createRemoteJWKSet` with the same pinned `algorithms`. Rotation is built in — create a **standby key**, wait for JWKS caches to pick it up, then promote it: old tokens stay valid until expiry and no service redeploys or re-copies anything.

**Verify:** grep every service's env/config for the legacy shared JWT secret → zero hits outside Supabase itself; test feeds an HS256 token signed with a guessed secret → 401.
