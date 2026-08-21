# 📡 Realtime & Client-Side Channels

WebSockets, Supabase Realtime, SSE, postMessage, and iframes all bypass the HTTP middleware where your auth lives — every channel needs its own auth, its own origin check, and its own validation.

## TL;DR — the rules

1. WebSockets: `wss://` only; authenticate the upgrade request itself; exact-match Origin allowlist (browsers do NOT enforce same-origin for WS — CSWSH).
2. Re-authorize and Zod-validate every inbound WS message; never put tokens in WS URLs; cap connections and messages per user.
3. Supabase Realtime Broadcast/Presence are public by default — table RLS does NOT cover them. Set `private: true`, write RLS on `realtime.messages`, disable public access.
4. SSE handlers get per-handler auth; use short-lived single-use stream tickets, never long-lived tokens in query strings; check Origin/`Sec-Fetch-Site`.
5. Never accumulate streamed LLM chunks into `innerHTML`; set idle timeouts and concurrent-stream caps.
6. postMessage: exact-match `event.origin`, no `*` targetOrigin with sensitive data, Zod-validate `event.data`, MessageChannel for widgets.
7. Iframes: `sandbox` + minimal `allow=` on anything third-party or user-influenced; never `allow-same-origin` + `allow-scripts` on user content; gesture-gate one-click confirmations (DoubleClickjacking).

## Rule 1 — Authenticate the WebSocket upgrade; exact Origin allowlist

Browsers do not apply the same-origin policy to WebSocket handshakes: any page on the web can open a socket to your server, and the browser attaches your cookies. That is Cross-Site WebSocket Hijacking (CSWSH) — the WS equivalent of CSRF, and cookie auth alone does nothing against it. The upgrade request is the only moment you see HTTP headers, so auth and Origin both happen there, and only over `wss://`.

```ts
// ❌ WRONG — accepts any upgrade; cookies ride along from evil.example
wss.on('connection', (ws) => handle(ws));

// ✅ RIGHT — verify auth + exact Origin during the upgrade, before accepting
const ALLOWED_ORIGINS = new Set([env.APP_ORIGIN]); // e.g. https://app.example.com
server.on('upgrade', async (req, socket, head) => {
  const origin = req.headers.origin;
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return socket.destroy(); // exact match, no endsWith()
  const session = await getSessionFromRequest(req);   // cookie or Sec-WebSocket-Protocol token
  if (!session) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return socket.destroy(); }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, session));
});
```

Pair the cookie with a per-connection token (e.g. passed via the `Sec-WebSocket-Protocol` header or a first authenticated frame) so a hijacked cookie alone can't open a channel. Vercel serverless functions don't hold WS connections — terminate sockets on a dedicated host or use managed realtime (Rule 3) instead of hand-rolling.

**Verify:** ch15 test opens a WS with `Origin: https://evil.example` and a valid session cookie → connection refused; grep for `ws://` in client code → zero outside localhost.

## Rule 2 — Re-authorize and validate every message; no tokens in WS URLs; rate caps

Auth at upgrade time is not authorization forever: sockets live for hours, sessions get revoked, and every inbound frame is untrusted input that skipped your HTTP validation stack. Tokens in the WS URL (`wss://…?token=`) land in server logs, proxies, and browser history — same ban as query-string secrets anywhere else.

```ts
// ❌ WRONG — trusts the frame; channel authz checked once at connect
ws.on('message', (raw) => db.insert(JSON.parse(raw)));

// ✅ RIGHT — Zod parse + per-message re-authorization + rate cap
const Msg = z.object({ channel: z.string().max(64), body: z.string().max(4096) });
ws.on('message', async (raw) => {
  if (!(await rateLimit(session.userId, 'ws-msg'))) return ws.close(1008, 'rate'); // ch07
  const msg = Msg.safeParse(JSON.parse(String(raw)));
  if (!msg.success) return ws.close(1008, 'invalid');
  if (!(await canAccessChannel(session.userId, msg.data.channel))) return ws.close(1008, 'forbidden');
  await handle(session, msg.data);
});
```

Cap concurrent connections per user and messages per connection per second — one client holding thousands of sockets is a DoS you never rate-limited because it isn't HTTP ([07 — Rate Limiting](./07-rate-limiting.md)).

**Verify:** test sends a frame for another tenant's channel on an authenticated socket → closed with 1008; grep for `token=` inside `new WebSocket(` URLs → zero.

## Rule 3 — Supabase Realtime: `private: true` or it's public

Supabase Broadcast and Presence channels are **public by default, and your table RLS policies do not cover them** — RLS on `messages` protects the table, not the channel; any client with your anon key can subscribe to `room:42` and read every broadcast. Authorization for Realtime lives in RLS policies on the `realtime.messages` table, and only fires when the channel is created with `private: true`.

```ts
// ❌ WRONG — public channel; anyone with the anon key gets the tenant's events
supabase.channel('org:42:updates').on('broadcast', { event: '*' }, cb).subscribe();

// ✅ RIGHT — private channel, authorized by RLS on realtime.messages
supabase.realtime.setAuth(session.access_token);      // re-call after every token refresh
supabase.channel('org:42:updates', { config: { private: true } })
  .on('broadcast', { event: '*' }, cb).subscribe();
```

```sql
-- ✅ RIGHT — scope topics to the caller's tenant (extends 04-database-rls.md)
create policy "members read their org topics" on realtime.messages
  for select to authenticated
  using ( realtime.topic() like 'org:' || (select org_id from members
          where user_id = (select auth.uid())) || ':%' );
```

Also disable "Allow public access" in the Realtime settings so an accidentally-public channel fails closed, and call `setAuth()` again after token refresh or the socket keeps the old claims.

**Verify:** ch15 cross-tenant test: user A subscribes to `org:B:*` with `private: true` → subscription rejected; grep `supabase.channel(` call sites for missing `private: true` → zero.

## Rule 4 — SSE: per-handler auth and single-use stream tickets

`EventSource` cannot send an `Authorization` header, so AI-generated SSE code either leaves the endpoint unauthenticated or drops a long-lived token into the query string — logged everywhere, replayable by anyone. An SSE route is a route: it gets the same session check as any handler, and if you must pass credentials in the URL, mint a short-lived single-use ticket for exactly that stream.

```ts
// ❌ WRONG — session JWT in the query string, no auth on the handler
// new EventSource(`/api/stream?token=${accessToken}`)

// ✅ RIGHT — POST mints a 30s single-use ticket; the stream consumes it atomically
export async function GET(req: Request) {
  if ((req.headers.get('sec-fetch-site') ?? 'same-origin') !== 'same-origin')
    return new Response(null, { status: 403 });                    // plus Origin check when present
  const ticket = new URL(req.url).searchParams.get('ticket');
  const userId = await redeemStreamTicket(ticket);                 // single-use, ≤30s TTL, deleted on read
  if (!userId) return new Response(null, { status: 401 });
  return streamFor(userId, { idleTimeoutMs: 60_000 });             // idle timeout + per-user stream cap
}
```

Rendering the stream: append chunks with `textContent` (or a sanctioned sanitizer for markdown) — accumulating LLM output into `innerHTML` is a self-inflicted XSS the moment a prompt-injected model emits `<img onerror=…>` (cross-link [13 — SSRF & LLM](./13-ssrf-and-llm.md)).

**Verify:** unauthenticated `curl` to the SSE route → 401; a replayed ticket → 401; grep client code for `EventSource(` URLs containing `token=` → zero.

## Rule 5 — postMessage: exact origins both ways, validated payloads

`message` listeners are a public entry point: any page that can get a reference to your window can post to it. Substring and regex origin checks (`origin.includes('example.com')` matches `example.com.evil.io`) are a recurring compromise class — Microsoft's MSRC wrote up exactly this pattern in 2025. And `postMessage(data, '*')` with sensitive data hands it to whoever ends up in that frame.

```ts
// ❌ WRONG — substring origin check + wildcard send
window.addEventListener('message', (e) => {
  if (e.origin.includes('example.com')) applyState(e.data);
});
frame.contentWindow.postMessage({ session }, '*');

// ✅ RIGHT — exact-match allowlist, Zod on event.data, exact targetOrigin
const PEERS = new Set(['https://widget.example.com']);
const Inbound = z.object({ kind: z.literal('resize'), height: z.number().int().max(4000) });
window.addEventListener('message', (e) => {
  if (!PEERS.has(e.origin)) return;
  const msg = Inbound.safeParse(e.data);
  if (msg.success) applyState(msg.data);
});
frame.contentWindow.postMessage(payload, 'https://widget.example.com');
```

For an ongoing widget conversation, hand the iframe one `MessageChannel` port in a bootstrap message — afterwards traffic flows over the private port pair instead of the window-global broadcast surface.

**Verify:** grep `addEventListener('message'` sites for `includes(`/`endsWith(`/regex origin checks and grep for `postMessage(.*'\*'` → zero on sensitive payloads.

## Rule 6 — Iframes: sandbox everything untrusted; gesture-gate one-click confirmations

Your `frame-ancestors 'none'` ([10 — Headers, CSP & CORS](./10-headers-csp-cors.md)) controls who frames *you*; this rule is what *you* frame. Any third-party or user-influenced document gets `sandbox` with the minimum grants — and `allow-same-origin` + `allow-scripts` together on same-site user content is no sandbox at all: the framed script runs with your origin and can remove its own sandbox.

```tsx
// ❌ WRONG — user-supplied content, fully privileged, camera/payment inherited
<iframe src={userContentUrl} />

// ✅ RIGHT — minimal sandbox + explicit permissions policy for the frame
<iframe
  src={userContentUrl}
  sandbox="allow-scripts"            /* never together with allow-same-origin for user content */
  allow="camera 'none'; microphone 'none'; payment 'none'"
  referrerPolicy="no-referrer"
/>
```

DoubleClickjacking (2024–25 disclosure) bypasses `frame-ancestors` entirely: an attacker page prompts a double-click and swaps your OAuth-consent/delete-account window under the second click — no iframe involved. Defense is in your UI: sensitive one-click confirmations must require a real prior gesture in your own page (buttons disabled until mousedown/pointer movement inside the page, or a two-step confirm).

**Verify:** grep for `<iframe` without a `sandbox` attribute where `src` isn't a first-party constant → zero; ch15 e2e asserts destructive confirm buttons are disabled until an in-page gesture occurs.

---

Previous: [17 — Client Data Protection](./17-client-data-protection.md) · Next: [25 — Deployment & Infrastructure](./25-deployment-infrastructure.md)
