# 🗃️ Caching & CDN Security

A shared cache turns one user's response into everyone's response. Personalized data is never cacheable by default, cache keys always include the identity they serve, and the CDN only caches what you explicitly allowlisted.

## TL;DR — the rules

1. Authenticated or personalized responses are `Cache-Control: private, no-store` — never cacheable by a shared cache (CDN, proxy, framework data cache).
2. Caching is allowlist, not default: only explicitly public, identical-for-everyone responses get `public` + `s-maxage`.
3. Any server-side cache entry that stores user-scoped data includes the user/tenant ID in its cache key.
4. Never wrap an auth or entitlement check in a cache — a stale paywall is an open paywall.
5. Defend against web cache deception: exact route matching, correct `Content-Type`, `no-store` on account routes regardless of URL suffix.
6. Everything that varies the response is either in the cache key or in `Vary` — reflected unkeyed inputs are cache poisoning.
7. Sensitive pages (account, billing, admin) also get browser-cache protection: `no-store` so back-button and shared machines don't replay them.
8. Verify caching in the deployed environment, not just locally — CDN behavior only exists in production.

## Rule 1 — Personalized responses are never shared-cacheable

**Why:** This failure has hit the biggest names: Steam's 2015 Christmas incident served cached account pages (with partial payment data) of one user to other users after a caching config change; the March 2023 ChatGPT outage exposed other users' chat titles and partial billing data through a cache/connection reuse bug. One misplaced `public` or `s-maxage` on an authenticated route reproduces this in any app.

```ts
// ❌ WRONG — authenticated API response marked shared-cacheable
export async function GET() {
  const user = await requireUser();
  return NextResponse.json(await getDashboard(user.id), {
    headers: { 'Cache-Control': 'public, s-maxage=300' },
  });
}

// ✅ RIGHT — personalized responses opt out of shared caches entirely
export async function GET() {
  const user = await requireUser();
  return NextResponse.json(await getDashboard(user.id), {
    headers: { 'Cache-Control': 'private, no-store' },
  });
}
```

**Verify:** integration test logs in as user A and user B, fetches the same authenticated route, and asserts (a) different bodies and (b) `Cache-Control` contains `no-store` or `private`; grep API routes for `s-maxage|public` and require each hit to be on an allowlisted public endpoint.

## Rule 2 — Caching is an explicit allowlist

**Why:** AI-generated code adds `revalidate`, `force-cache`, or CDN page rules to "make it fast" without asking *for whom* the response is identical. Default-deny inverts the failure mode: forgetting a cache header makes the app slower, not breached.

```ts
// ✅ RIGHT — one documented allowlist, everything else uncached
// docs/cache-allowlist.md: /api/pricing, /api/changelog, /blog/* are public+identical
export const revalidate = 3600; // ONLY on routes from the allowlist
```

**Verify:** CI grep for `revalidate|force-cache|s-maxage|use cache` and diff the hit list against the committed allowlist file; new hit not in the allowlist fails the check.

## Rule 3 — User-scoped cache entries carry the user in the key

**Why:** The classic Next.js data-leak: `unstable_cache`/`use cache`/`cache()` wrapping a function that reads the *current* user, keyed only on the function args. The first user to warm the cache donates their data to every later caller. Same bug exists with hand-rolled Redis keys like `dashboard:v1`.

```ts
// ❌ WRONG — key has no user; first caller's data is served to everyone
const getSettings = unstable_cache(async () => {
  const { userId } = await auth();
  return db.settings.find(userId);
}, ['settings']);

// ✅ RIGHT — identity resolved OUTSIDE, and baked into the key
async function getSettingsFor(userId: string) {
  return unstable_cache(
    () => db.settings.find(userId),
    ['settings', userId],           // key includes the identity it serves
  )();
}
```

Also true for Redis/Upstash: `cache:${userId}:dashboard`, never `cache:dashboard`.

**Verify:** grep every `unstable_cache|use cache|@cache|cache.set` site: if the wrapped code touches `auth()`, `cookies()`, `session`, or a `userId`, the key array/string must contain that ID — a two-user integration test on one cached path proves isolation.

## Rule 4 — Never cache authorization

**Why:** Caching an entitlement check ("is this user subscribed?") means revocation doesn't revoke: a canceled subscription, removed team member, or banned user keeps access until TTL expiry. Combined with stale-while-revalidate, the stale (authorized) answer is served *while* the fresh (denied) one is computed. See [payments](12-payments.md) for the server-side entitlement rule this protects.

```ts
// ❌ WRONG — paywall answer cached for an hour
const isSubscribed = unstable_cache(checkSubscription, ['sub', userId], { revalidate: 3600 });

// ✅ RIGHT — authz is computed per request; cache the expensive DATA, not the DECISION
const ok = await checkSubscription(userId);   // hits DB/provider every time
if (!ok) return new Response('Payment required', { status: 402 });
```

**Verify:** test flips the entitlement flag in the DB and asserts the very next request is denied — no waiting, no TTL.

## Rule 5 — Web cache deception: don't let the URL decide cacheability

**Why:** Omer Gil's 2017 PayPal disclosure: requesting `/account/settings/x.css` made the CDN treat a personalized page as a static asset and cache it — the attacker then fetched the victim's cached account page. Any CDN rule like "cache everything ending in .css/.js/.jpg" recreates this.

```text
❌ WRONG  CDN rule: cache by file extension (*.css → cache 1 year)
✅ RIGHT  Cache by exact route + response Content-Type; authenticated
          routes send no-store, which the CDN honors REGARDLESS of path
```

In Next.js/Vercel this mostly holds by default (caching follows the route, not the URL suffix), so the rule is: don't break it with custom CDN page rules, rewrites that catch arbitrary suffixes, or `Cache-Control` overrides at the edge.

**Verify:** deployed check: `curl -H "Cookie: $SESSION" https://app.example.com/account/settings/x.css` then fetch the same URL without the cookie — assert 404/redirect and a cache MISS (`x-vercel-cache`/`cf-cache-status`), never the authenticated body.

## Rule 6 — Poisoning: every response-shaping input is keyed or dropped

**Why:** Cache poisoning (James Kettle's research line) works by finding an *unkeyed* input the server reflects: `X-Forwarded-Host` reflected into absolute URLs or `<script src>`, an `Origin` echoed into `Access-Control-Allow-Origin`, a locale header picking the variant. One attacker request with a malicious header is then served to every user hitting that cache entry.

```ts
// ❌ WRONG — header the cache doesn't key on, reflected into a cached page
const base = req.headers.get('x-forwarded-host');   // attacker-controlled
return new Response(renderPage({ assetBase: `https://${base}` }), {
  headers: { 'Cache-Control': 'public, s-maxage=3600' },
});

// ✅ RIGHT — absolute URLs come from config, not request headers
const base = env.NEXT_PUBLIC_APP_URL;               // validated at boot, see ch. 05
```

If a header legitimately varies a cached response (e.g. `Accept-Language`), declare it: `Vary: Accept-Language` — and keep the `Vary` list tiny, since each entry multiplies cache entries.

**Verify:** grep cached routes for reads of `x-forwarded-*`, `host`, `origin`, `referer` flowing into the response body/headers → zero, or the header appears in `Vary`; a test sends a hostile `X-Forwarded-Host` and asserts it never appears in any cacheable response.

## Rule 7 — Sensitive pages don't linger in the browser either

**Why:** `private` only excludes *shared* caches — the browser still stores the page, so back-button on a shared machine, or disk forensics, replays the billing page after logout. OWASP session management guidance: sensitive content gets `no-store`.

```ts
// ✅ RIGHT — account/billing/admin layouts
headers: { 'Cache-Control': 'no-store' }
```

**Verify:** header assertion test on `/account`, `/billing`, `/admin` responses: `Cache-Control` contains `no-store`; manual check: log out, press back — assert redirect, not a rendered snapshot.

## Rule 8 — Verify caching where the CDN actually runs

**Why:** Local dev has no CDN; `next dev` disables most caching. Every rule above can pass locally and fail in production, which is exactly where the shared cache exists. Vercel exposes `x-vercel-cache` (`HIT/MISS/STALE`), Cloudflare `cf-cache-status` — use them.

```bash
# ✅ smoke test against the deployed URL, in CI after deploy
curl -sI https://app.example.com/api/me -H "Cookie: $SESSION_A" | grep -i 'cache-control: .*no-store'
curl -sI https://app.example.com/api/pricing | grep -i 'x-vercel-cache'   # public route: expect HIT on 2nd call
```

**Verify:** a post-deploy smoke job asserts: authenticated routes never return `x-vercel-cache: HIT`; the two-user isolation test from Rule 3 runs against the preview deployment, not just localhost.

---

Related chapters: [headers & CORS](10-headers-csp-cors.md) (the header machinery), [payments](12-payments.md) (entitlements this protects), [self-verification](15-testing-verification.md) (where these tests live in CI).
