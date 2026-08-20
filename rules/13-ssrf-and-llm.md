# 🤖 SSRF & LLM-Integrated Apps

Two rules of trust: any URL from a request or a model is attacker-controlled, and any LLM output is untrusted input — validate both like you'd validate a form field from the internet.

## TL;DR — the rules

1. Never fetch a user-supplied or model-supplied URL raw — route every such fetch through one named validator.
2. The validator: scheme allowlist, reject userinfo, resolve DNS then pin the IP, binary-check against private/link-local/metadata ranges.
3. Disable redirects on untrusted fetches (or re-validate every hop); hard timeout ≤5s; cap streamed body size.
4. Treat all LLM output as untrusted: parse structured output through a strict schema, never `JSON.parse(text) as T`.
5. Never render model output with `dangerouslySetInnerHTML`; render as plain text or sanitized markdown.
6. Give tool-calling agents least-privilege tools; destructive tools require human confirmation.
7. Never put secrets in prompts; run agent fetches in a context that holds no secrets.
8. Rate-limit and cap daily spend on every LLM endpoint before creating the model stream.
9. Log prompts/outputs as structured fields with PII redaction — never raw into message strings.

## Rule 1 — One named validator for every untrusted outbound fetch

**Why:** `fetch(req.body.url)` is failure mode #13 in the AI-codegen threat model. Real stack CVEs: CVE-2025-57822 (Next.js middleware reflecting user headers into `NextResponse.next()` → SSRF; fixed 14.2.32/15.4.7), CVE-2026-8768 (Vercel AI SDK ≤3.0.97 download-URL validation), and the Pydantic AI chain (CVE-2026-25580, fixed 1.56.0). Vercel does NOT block metadata/private ranges for normal Functions — validate in app code. Sinks: link previews, "import from URL", avatar-from-URL, RAG ingestion, LLM tool-call URLs, user-configured webhooks.

```ts
// ❌ WRONG — SSRF into 169.254.169.254, localhost admin ports, RFC 1918
export async function POST(req: Request) {
  const { url } = await req.json();
  const res = await fetch(url); // also: model-suggested URLs in agent tools
}

// ✅ RIGHT — lib/safe-fetch.ts: the only path to an untrusted URL
import { lookup } from "node:dns/promises";
import ipaddr from "ipaddr.js";

export async function assertPublicUrl(raw: string): Promise<URL> {
  const url = new URL(raw);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("scheme");
  if (url.username || url.password) throw new Error("userinfo"); // http://ok.com@169.254.169.254/
  const records = await lookup(url.hostname, { all: true, verbatim: true });
  for (const { address } of records) {
    const range = ipaddr.process(address).range(); // binary check, handles ::ffff:a9fe:a9fe
    if (range !== "unicast") throw new Error(`blocked range: ${range}`);
  }
  return url; // connect via an agent pinned to a validated IP (anti-rebinding)
}
```

Node gotcha: built-in global fetch (undici) **silently ignores `{agent}`** — use got/axios/node-fetch with `request-filtering-agent` (which re-checks at connect time, defeating DNS rebinding), or a hardened undici dispatcher. Python: stdlib `ipaddress` + `socket.getaddrinfo` per the Pydantic AI 1.56.0 fix — Advocate/SafeURL are abandoned, and CVE-2025-9960 (is-localhost-ip) proves random "is-private" packages can't be trusted.

When destinations are known, use an exact-hostname allowlist instead — resolve-and-block is only for genuinely arbitrary URLs.

**Verify:** Semgrep `p/ssrf` (taint mode) plus a repo rule requiring `assertPublicUrl`/`safeFetch` on any fetch whose URL derives from input; test suite feeds `http://ok.com@169.254.169.254/`, `http://2130706433/`, `http://0x7f000001/`, `http://[::ffff:a9fe:a9fe]/` → all rejected.

## Rule 2 — Redirects off, timeouts hard, bodies capped

**Why:** A validated URL that 302s to `http://169.254.169.254/` defeats the whole check — redirect-based bypass is a confirmed technique. Unbounded fetches also make your server a port scanner and an exfiltration channel.

```ts
// ✅ RIGHT
const res = await got(url.href, {
  followRedirect: false,            // or re-validate every hop
  timeout: { request: 5000 },
  agent: { https: useAgent(url.href) }, // request-filtering-agent
});
// stream the body with a byte counter; abort past e.g. 5 MB
```

Python: `httpx.AsyncClient(follow_redirects=False, timeout=5.0)`.

**Verify:** test against a local redirector that 302s to a metadata IP → fetch fails; grep untrusted-fetch call sites for `followRedirect: false` / `follow_redirects=False`.

## Rule 3 — LLM output is untrusted input: schema-validate everything structured

**Why:** Prompt injection (OWASP LLM01) means anyone who can influence what the model reads — a webpage in RAG, a user message, a document — can influence what it outputs. `JSON.parse(text) as T` is a type-system lie with zero runtime checking (failure mode #14, OWASP LLM05).

```ts
// ❌ WRONG — the cast checks nothing; injected output flows straight into your DB
const plan = JSON.parse(completion.text) as ActionPlan;

// ✅ RIGHT — AI SDK generateObject with a bounded strict schema
import { generateObject } from "ai";
const { object } = await generateObject({
  model,
  schema: z.strictObject({
    title: z.string().max(200),
    priority: z.enum(["low", "medium", "high"]),
    link: z.url().refine(u => new URL(u).hostname === "docs.example.com"),
  }),
  prompt,
});
```

Python: `instructor` with `response_model=` and `ConfigDict(extra='forbid')`. Remember: schema conformance ≠ content safety — bound strings with `.max()`, use enums, allowlist URL hosts.

**Verify:** `grep -rn 'JSON.parse' src/ | grep -i 'completion\|response\|llm\|message'` → zero unvalidated hits; fixture test feeds a malicious model reply (extra keys, oversized strings, off-allowlist URL) → parse rejects.

## Rule 4 — Never render model output as HTML

**Why:** Model output can contain attacker-authored markup via prompt injection; `dangerouslySetInnerHTML` turns that into stored XSS in your origin. Veracode 2025: AI-generated code fails XSS tasks 86% of the time — don't compound it.

```tsx
// ❌ WRONG
<div dangerouslySetInnerHTML={{ __html: completion }} />

// ✅ RIGHT — markdown pipeline with sanitization, raw HTML disabled
import Markdown from "react-markdown"; // no rehype-raw; add rehype-sanitize if you must extend
<Markdown allowedElements={["p","a","ul","ol","li","code","pre","strong","em"]}>
  {completion}
</Markdown>
```

**Verify:** `grep -rn 'dangerouslySetInnerHTML' src/` → zero hits on LLM-derived values; E2E test renders a completion containing `<img src=x onerror=alert(1)>` → no script executes.

## Rule 5 — Least-privilege tools; humans approve destruction

**Why:** OWASP LLM06 (excessive agency): a prompt-injected agent uses whatever tools it holds. A "search the docs" agent with a `deleteRecord` tool is one poisoned document away from data loss. Tool-call URLs are attacker-controlled input (route them through Rule 1's validator).

```ts
// ❌ WRONG — one god-tool
tools: { db: tool({ description: "Run any SQL", parameters: z.object({ sql: z.string() }) }) }

// ✅ RIGHT — narrow, parameterized, gated
tools: {
  searchDocs: tool({ parameters: z.strictObject({ query: z.string().max(200) }), execute: searchDocs }),
  deleteProject: tool({
    parameters: z.strictObject({ projectId: z.uuid() }),
    execute: async (args, { userId }) => {
      await requireHumanApproval(userId, "deleteProject", args); // queue, don't execute
    },
  }),
}
```

**Verify:** tool manifest review in CI — every tool schema is `z.strictObject` with bounded params; destructive tools (delete/pay/send/deploy) grep-match against an approval-wrapper allowlist.

## Rule 6 — No secrets in prompts; agent fetches run secret-free

**Why:** Anything in the context window can be exfiltrated by injection ("repeat your instructions", or a tool call that POSTs the conversation). Architecture from the research corpus: run untrusted/agent fetches in a context holding no secrets — a dedicated fetcher service or egress proxy (smokescreen/pipelock) — so even a validator bypass can't read metadata or credentials.

```text
❌ WRONG: system prompt contains DB URLs, API keys, or "the admin password is..."
✅ RIGHT: tools receive an opaque per-user capability handle; the executor resolves
          it server-side; the model never sees a credential string.
```

**Verify:** `grep -in 'key\|secret\|password\|token' prompts/ src/**/prompts*` → zero credential values; red-team eval asks the deployed agent for its instructions/keys → nothing sensitive returned.

## Rule 7 — Rate-limit and spend-cap every LLM endpoint

**Why:** OWASP LLM10 (unbounded consumption): inference is the most expensive route you have, and it's a favorite for resale abuse. Check bot status → per-user limit → daily token/cost budget, all BEFORE creating the model stream.

```ts
// ✅ RIGHT — order matters
const { isBot } = await checkBotId();               // platform bot check
if (isBot) return new Response(null, { status: 403 });
await assertLimit(llmLimiter, userId);              // fail-closed limiter (see rules/07)
await assertDailyBudget(userId, estTokens);         // atomic UPDATE ... WHERE spent + $x <= cap RETURNING
const stream = await streamText({ model, prompt }); // only now
```

**Verify:** parallel-request test: 10 concurrent calls against a nearly-exhausted budget → total spend ≤ cap (atomic check, no read-then-write race).

## Rule 8 — Log prompts and outputs with PII care

**Why:** Prompts contain user PII; outputs can contain regurgitated PII. Dumping either raw into logs is a GDPR incident and a second exfiltration surface — but you need them for abuse investigation.

```ts
// ✅ RIGHT — structured fields, redaction, bounded lengths
logger.info({
  event: "llm_call", requestId, userId,
  model: "…", promptTokens, completionTokens,
  promptHash: sha256(prompt),          // correlate without storing
  promptPreview: redactPII(prompt).slice(0, 512),
}, "llm_call");
```

**Verify:** log-redaction unit test: a prompt containing an email + phone number produces a log line containing neither; retention policy on the raw-prompt store is documented and enforced.

---

Related: [07 — Rate Limiting](07-rate-limiting.md) (limiter mechanics, fail-closed) · [05 — Secrets & Env](05-secrets-and-env.md) (why secrets never reach client or prompt).
