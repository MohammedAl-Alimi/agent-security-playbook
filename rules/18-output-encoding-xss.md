# 🧼 Output Encoding & XSS

Frameworks escape by default; every XSS you ship comes from the handful of sinks that opt out — so ban the sinks, funnel legitimate HTML through one sanitizer, and test with real payloads.

## TL;DR — the rules

1. Never pass user- or third-party-derived values to `dangerouslySetInnerHTML`/`innerHTML`/`insertAdjacentHTML`/`v-html` — grep must show zero unsanctioned hits.
2. All legitimate rich HTML flows through one sanctioned sanitizer module (DOMPurify or rehype-sanitize), applied at the render site — never write-time-only, never ad-hoc regex.
3. User-supplied URLs in `href`/`src` pass a scheme allowlist (`https:`, `mailto:`); reject `javascript:` and `data:` — CSP does not cover these sinks.
4. Render LLM output and user markdown with a markdown renderer whose raw-HTML passthrough is disabled.
5. Entity-escape (`<`, `>`, `&`, U+2028/U+2029) any JSON embedded in `<script>` tags; prefer serializers that do it for you.
6. Enforce `require-trusted-types-for 'script'` where supported; feature-detect the native Sanitizer API with a DOMPurify fallback.
7. CI runs a Semgrep/lint rule over every innerHTML- and eval-family sink, and an E2E test stores an XSS payload in every user-writable field.

## Rule 1 — Ban innerHTML-family sinks on untrusted data

ASVS 5.0 V1 (Encoding and Sanitization) makes context-aware output encoding a first-class requirement, and the OWASP XSS Prevention Cheat Sheet's core rule is the same: untrusted data never reaches an HTML-interpreting sink unencoded. React/Vue escape interpolated text automatically — which is exactly why every framework XSS in practice goes through the escape hatches: `dangerouslySetInnerHTML`, `v-html`, `element.innerHTML`, `insertAdjacentHTML`, `document.write`. This applies to *ordinary* user data (display names, bios, comments) and third-party API responses, not just LLM output.

```tsx
// ❌ WRONG — stored XSS: any user's bio executes in every viewer's session
export function ProfileBio({ bio }: { bio: string }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}

// ✅ RIGHT — default interpolation is auto-escaped; no sink, no XSS
export function ProfileBio({ bio }: { bio: string }) {
  return <div className="whitespace-pre-wrap">{bio}</div>;
}
```

Plain text is the default; rich HTML is the exception that must go through Rule 2. The same discipline applies server-side: HTML email bodies interpolating user values are the same sink in a different renderer (Papra GHSA-6f8x-2rc9-vgh4 was exactly this).

**Verify:** `grep -rn 'dangerouslySetInnerHTML\|innerHTML\|insertAdjacentHTML\|v-html\|document.write' src/ app/` → every hit is inside the one sanctioned module from Rule 2, or has a written justification proving the value is static.

## Rule 2 — One sanctioned sanitizer module, applied at the render site

If rich HTML is a real feature (CMS content, rich-text comments), all of it flows through a single module wrapping DOMPurify (or rehype-sanitize in a unified/remark pipeline) with a documented allowlist. One module, because two call sites drift and the second one quietly loses `FORBID_ATTR`. At the *render* site, because write-time sanitization rots: DOMPurify bypasses get patched over time, old rows stay dirty, and new ingestion paths (imports, webhooks, admin edits) skip the write-path hook. Hand-rolled regex "sanitizers" are findings, not controls — the OWASP DOM-based XSS Prevention Cheat Sheet exists because HTML parsing is not regular.

```tsx
// ❌ WRONG — ad-hoc regex at write time; render still trusts the DB
const clean = html.replace(/<script.*?<\/script>/gi, '');   // bypassable a dozen ways
await db.insert(posts).values({ body: clean });

// ✅ RIGHT — lib/sanitize.ts is the only module allowed to touch the sink
import DOMPurify from 'isomorphic-dompurify';
const POLICY = {
  ALLOWED_TAGS: ['p', 'a', 'em', 'strong', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre'],
  ALLOWED_ATTR: ['href'],
  ALLOWED_URI_REGEXP: /^https?:|^mailto:/i,
};
export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, POLICY);
}
// render site: <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(post.body) }} />
```

Store what the user submitted; sanitize what the browser renders. Sanitizing at write time *additionally* is fine (defense in depth) — it is never the only layer.

**Verify:** every `dangerouslySetInnerHTML` hit from Rule 1's grep wraps a `sanitizeHtml(` call from `lib/sanitize.ts`; a unit test asserts `sanitizeHtml('<img src=x onerror=alert(1)>')` strips the handler.

## Rule 3 — Scheme allowlist for user-supplied URLs

`href` and `src` are XSS sinks that auto-escaping does not protect: `<a href={userUrl}>` renders fine and `javascript:alert(document.cookie)` executes on click. CSP does not block `javascript:` navigation in all sinks, so the control belongs at the data boundary. Allowlist schemes (`https:`, `mailto:`); never blocklist — `JaVaScRiPt:`, whitespace, and control-character variants defeat string matching, so parse with `new URL()` and compare `protocol`.

```tsx
// ❌ WRONG — javascript: and data: URLs pass straight through
<a href={profile.website}>{profile.website}</a>

// ✅ RIGHT — parse, check protocol against an allowlist, else drop the link
const SAFE_SCHEMES = new Set(['https:', 'mailto:']);
export function safeUrl(raw: string): string | null {
  try {
    const url = new URL(raw);
    return SAFE_SCHEMES.has(url.protocol) ? url.href : null;
  } catch { return null; }
}
```

Better: enforce it at parse time (extends [Input Validation](03-input-validation.md)) with a Zod refinement on every URL-bearing field, so `javascript:` never reaches the database at all. `data:` URLs are rejected too — `data:text/html` documents run script in some contexts, and there is no legitimate reason for a user "website" field to carry one.

**Verify:** `grep -rn 'href={' src/ app/` — every hit binding a user-derived value goes through `safeUrl()`; a fixture test posts `javascript:alert(1)` and `data:text/html,<script>alert(1)</script>` into each URL field and asserts 400 or a dead link.

## Rule 4 — Markdown and LLM output render with HTML disabled

Markdown renderers pass raw inline HTML through by default in many configurations — so "we render markdown, not HTML" is only true if you turned HTML off. LLM output is untrusted for the same reason user input is (an injected prompt can make the model emit `<img onerror=...>`; see [SSRF & LLM](13-ssrf-and-llm.md)). The rule: react-markdown-style renderers with no `rehype-raw`, or a pipeline where the only HTML that survives went through rehype-sanitize.

```tsx
// ❌ WRONG — rehype-raw re-enables embedded HTML; model output becomes a sink
<ReactMarkdown rehypePlugins={[rehypeRaw]}>{llmAnswer}</ReactMarkdown>

// ✅ RIGHT — HTML stays disabled; markdown formatting still works
<ReactMarkdown>{llmAnswer}</ReactMarkdown>
```

```python
# ✅ RIGHT — Python: escape HTML at render, then convert markdown
import markdown
html = markdown.markdown(user_text)          # keep default; never extensions that unescape
# and sanitize the result server-side (nh3/bleach) before it enters any template marked "safe"
```

Streaming LLM chunks are the same sink in slow motion: append them as text nodes, never accumulate into `innerHTML`.

**Verify:** `grep -rn 'rehype-raw\|rehypeRaw\|html: true' src/` → zero hits on untrusted-content pipelines; E2E test asks the chat UI to render `<img src=x onerror=alert(1)>` and asserts it appears as literal text.

## Rule 5 — Entity-escape JSON embedded in `<script>`

Serializing state into `<script>window.__STATE__ = {...}</script>` is a classic sink: `JSON.stringify` alone does not escape `<`, so a user value containing `</script><script>...` closes the tag and injects. The OWASP XSS Prevention Cheat Sheet's JSON rule: escape `<`, `>`, `&` to `\u003c`/`\u003e`/`\u0026` (and U+2028/U+2029, which break JS string literals) before embedding.

```tsx
// ❌ WRONG — name: "</script><script>steal()//" escapes the script block
<script dangerouslySetInnerHTML={{ __html: `window.__STATE__=${JSON.stringify(state)}` }} />

// ✅ RIGHT — entity-escape the serialized JSON before embedding
const safeJson = (v: unknown) =>
  JSON.stringify(v).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
<script dangerouslySetInnerHTML={{ __html: `window.__STATE__=${safeJson(state)}` }} />
```

In modern Next.js/RSC apps you rarely need this at all — props flow through the framework's own serializer. Prefer that; hand-built `<script>` state blobs need this escaping or a `<script type="application/json">` element read via `textContent`.

**Verify:** grep for `JSON.stringify` inside any `<script`-producing template → every hit routes through `safeJson`; unit test round-trips a value containing `</script>` and asserts the output contains no literal `<`.

## Rule 6 — Trusted Types and the native Sanitizer API

Trusted Types (`Content-Security-Policy: require-trusted-types-for 'script'`) turns every DOM XSS sink into a type error at runtime: `innerHTML` and friends refuse plain strings, so unsanctioned sinks fail loudly in supporting browsers instead of silently executing. Adopt it in report-only first, wire DOMPurify as the policy, then enforce. The native Sanitizer API (`Element.setHTML()`) is the standards-track replacement for DOMPurify but still has limited availability — feature-detect it and keep the DOMPurify fallback (see MDN's HTML Sanitizer API page and the WICG spec).

```ts
// ✅ RIGHT — one Trusted Types policy, backed by the Rule 2 sanitizer
if (window.trustedTypes?.createPolicy) {
  window.trustedTypes.createPolicy('default', {
    createHTML: (dirty) => sanitizeHtml(dirty),
  });
}

// ✅ RIGHT — native Sanitizer API where present, DOMPurify everywhere else
export function setSanitizedHtml(el: Element, dirty: string) {
  if ('setHTML' in el) (el as any).setHTML(dirty);
  else el.innerHTML = sanitizeHtml(dirty);
}
```

Add the header in report-only (`Content-Security-Policy-Report-Only`) alongside your existing CSP (see [Headers, CSP & CORS](10-headers-csp-cors.md)); violations reveal every sink you missed in Rule 1's grep.

**Verify:** response headers include `require-trusted-types-for 'script'` (report-only at minimum); the CSP report endpoint shows zero unresolved violations for a full release cycle before enforcing.

## Rule 7 — CI sink lint + stored-XSS E2E test

Greps rot; make Rules 1–4 machine-enforced. A Semgrep rule (or `eslint-plugin-react` `react/no-danger` plus `no-eval`) fails CI on any new innerHTML-family or eval-family sink outside the sanctioned module (extends [Supply Chain](14-supply-chain.md) and [Testing & Verification](15-testing-verification.md)). Then prove the whole chain end-to-end: one E2E test writes a canonical payload into *every* user-writable field and asserts it renders inert.

```yaml
# ✅ RIGHT — semgrep rule: any dangerouslySetInnerHTML outside lib/sanitize-render usage
rules:
  - id: unsanctioned-dangerously-set-inner-html
    languages: [typescript, tsx]
    severity: ERROR
    patterns:
      - pattern: dangerouslySetInnerHTML={{ __html: $X }}
      - pattern-not: dangerouslySetInnerHTML={{ __html: sanitizeHtml(...) }}
      - pattern-not: dangerouslySetInnerHTML={{ __html: safeJson(...) }}
    message: HTML sink must go through lib/sanitize.ts
```

```ts
// ✅ RIGHT — stored-XSS E2E: payload in, inert text out
const PAYLOAD = `"><img src=x onerror="window.__xss=1">`;
for (const field of USER_WRITABLE_FIELDS) {          // name, bio, comment, title, ...
  await submitField(page, field, PAYLOAD);
  await page.goto(viewUrlFor(field));
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
  await expect(page.getByText(PAYLOAD, { exact: false })).toBeVisible(); // escaped, visible as text
}
```

**Verify:** CI fails on a PR adding a bare `dangerouslySetInnerHTML`; the E2E suite covers every field enumerated from the shared schema module (Rule 7 of [Input Validation](03-input-validation.md)) and passes with `window.__xss` never set.

---

Next: [19 — Business Logic & Workflow Integrity](./19-business-logic.md) · also see [10 — Headers, CSP & CORS](./10-headers-csp-cors.md) and [13 — SSRF & LLM](./13-ssrf-and-llm.md)
