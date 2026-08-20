# 🧪 Input Validation

Parse, don't validate: every external input crosses a strict schema at the trust boundary, and the raw value is never touched again.

## TL;DR — the rules

1. Parse every external input through a schema before any other logic — route handlers, server actions, searchParams, route params, headers, cookies, webhook payloads, env, LLM output.
2. Use `z.strictObject()` (Zod v4) / Pydantic `ConfigDict(extra='forbid')` for all inbound payloads; `passthrough`/`looseObject` on untrusted input is banned.
3. Never spread raw input into a DB write — build the write object field-by-field from the parsed result; identity fields (`userId`, `orgId`, `role`) come from `auth()`, never from input.
4. Ban `z.coerce.boolean()` (parses `'false'` as `true`) — use `z.stringbool()`; guard `z.coerce.number()` against empty strings.
5. Model polymorphic payloads as discriminated unions, never one schema of optionals.
6. Validate env at boot: t3-env in `next.config.ts` / pydantic-settings at module import — a missing var is a build/boot failure.
7. Keep one shared schema module; derive variants with `.pick()/.omit()/.extend()` — no duplicated client/server schemas.
8. Client-side validation is UX only; the server re-parses everything.

## Rule 1 — Parse at every trust boundary

Veracode's 2025 GenAI report: AI-generated code introduces vulnerabilities in ~45% of tasks, mostly by *omission* — the handler works in the demo without validation, so none gets written. TypeScript types are erased at runtime; a typed Server Action is still a public POST endpoint accepting arbitrary JSON.

```ts
// ❌ WRONG — trusts the wire format because the type annotation says so
export async function POST(req: Request) {
  const body = await req.json() as { title: string; dueAt: string };
  await db.insert(tasks).values(body);            // body could be anything
}

// ✅ RIGHT — Schema.parse() is the first meaningful statement; `raw` dies here
import { TaskCreate } from '@/lib/schemas/tasks';
export async function POST(req: Request) {
  const raw = await req.json();
  const input = TaskCreate.parse(raw);            // throws 400 path on failure
  await db.insert(tasks).values({ title: input.title, dueAt: input.dueAt });
}
```

This applies equally to `searchParams` and route params (they arrive as `string | string[] | undefined`), headers, and LLM output — `JSON.parse(modelText) as T` is the same bug with a different source. Use `generateObject` with a Zod schema (or Python `instructor` with `response_model=`) so model output is schema-validated structured output, never trusted text.

**Verify:** grep every `app/api/**` handler and `'use server'` file for a `.parse(`/`.inputSchema(` call preceding any DB/fetch/LLM statement; a handler that reads its arguments first fails review.

## Rule 2 — Strict schemas: reject unknown keys loudly

Zod v4 verified semantics: default `z.object()` silently *strips* unknown keys; `.passthrough()`/`z.looseObject()` passes `admin: true` straight through. Pydantic v2 defaults to `extra='ignore'`. Silent stripping hides probing; passthrough is mass assignment.

```ts
// ❌ WRONG — attacker's { role: 'admin' } rides along
const UserUpdate = z.object({ name: z.string() }).passthrough();

// ✅ RIGHT — unknown keys are a 400, and the probe is visible in logs
const UserUpdate = z.strictObject({ name: z.string().min(1).max(120) });
```

```python
# ✅ RIGHT — Pydantic v2 body model
class UserUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=120)
# Keep query/path params lax (they arrive as strings); declare response_model= on every route.
```

**Verify:** `grep -rn 'passthrough\|looseObject' src/` → zero hits in inbound schemas; a fixture test posts a valid body plus `{"role":"admin"}` and asserts 400.

## Rule 3 — Never spread raw input into a DB write

Mass assignment is threat-model row #6: client-supplied `role`, `userId`, `orgId`, `amount` written verbatim. Even a parsed object should not be spread if the schema ever widens.

```ts
// ❌ WRONG — ...body writes whatever arrived; userId comes from the client
await db.update(profiles).set({ ...body }).where(eq(profiles.id, body.userId));

// ✅ RIGHT — explicit fields; identity from auth(), never from input
const { userId } = await auth();
const input = ProfileUpdate.parse(raw);           // schema has no userId/role field
await db.update(profiles)
  .set({ displayName: input.displayName, bio: input.bio })
  .where(eq(profiles.userId, userId));
```

**Verify:** grep input schemas for `userId|orgId|role|isAdmin|plan|amount` — every hit needs written justification; grep for `...body`/`...input` inside `insert(`/`update(`/`create(` calls → zero.

## Rule 4 — Coercion footguns

Verified on Zod 4.4.3 (issues #3924/#5501): `z.coerce.boolean().parse('false') === true` (any non-empty string is truthy) and `z.coerce.number().parse('') === 0`. A `?public=false` query param flips a resource public.

```ts
// ❌ WRONG — 'false' coerces to true; '' coerces to 0
const Q = z.object({ public: z.coerce.boolean(), limit: z.coerce.number() });

// ✅ RIGHT — stringbool parses 'false'/'0' correctly; non-empty guard before number
const Q = z.strictObject({
  public: z.stringbool(),
  limit: z.string().min(1).pipe(z.coerce.number().int().min(1).max(100)),
});
```

Also Zod v4 hygiene: top-level `z.email()`/`z.uuid()`/`z.url()` (the `.email()` method is deprecated); `.default()` now short-circuits without validating — use `.prefault()` for the old behavior; migrate with `npx zod-v3-to-v4`, don't hand-port v3 snippets.

**Verify:** `grep -rn 'coerce.boolean' src/` → zero hits (make it a Semgrep/CI rule).

## Rule 5 — Discriminated unions for polymorphic payloads

One schema of co-dependent optionals cannot express "field X is required only when type is Y", so invalid combinations parse.

```ts
// ✅ RIGHT
const Event = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('email'),   to: z.email(),  subject: z.string().max(200) }),
  z.strictObject({ type: z.literal('webhook'), url: z.url() }),
]);
```

```python
# ✅ RIGHT — Pydantic
Event = Annotated[Union[EmailEvent, WebhookEvent], Field(discriminator='type')]
```

**Verify:** a fixture test round-trips one valid payload per variant and one cross-variant hybrid (email type + webhook fields) — the hybrid must fail.

## Rule 6 — Validate env at boot, fail the build

Threat-model row #8: fail-open guards. next-forge (verified) silently no-ops security without `ARCJET_KEY` and returns 200 from an unconfigured Stripe webhook. The only survey starter that fails closed is full-stack-fastapi-template, whose pydantic-settings validator raises at boot on `'changethis'` secrets.

```ts
// ✅ RIGHT — src/env.ts, imported in next.config.ts so `next build` fails on a missing var
import { createEnv } from '@t3-oss/env-nextjs';
export const env = createEnv({
  server: { SUPABASE_SERVICE_ROLE_KEY: z.string().min(1), STRIPE_WEBHOOK_SECRET: z.string().min(1) },
  client: { NEXT_PUBLIC_SUPABASE_URL: z.url() },
  runtimeEnv: process.env, // eslint-disable-line -- the one sanctioned process.env read
  emptyStringAsUndefined: true,
});
```

Never set `SKIP_ENV_VALIDATION` in production — it disables everything. Python: a pydantic-settings `BaseSettings` instantiated at module import, with a `model_validator` that raises on placeholder secrets outside development.

**Verify:** delete a required var → `next build` fails; `grep -rn 'process.env.' src/ app/` hits only `env.ts`.

## Rule 7 — One shared schema module

Duplicated client/server schemas drift; the server copy is the one that quietly loses a constraint. dubinc/dub (24.5k★) keeps 40+ per-resource schemas in one module shared by routes, actions, forms, and OpenAPI.

```ts
// ✅ RIGHT — lib/schemas/tasks.ts is the single source; variants are derived
export const Task = z.strictObject({ id: z.uuid(), title: z.string().max(200), done: z.stringbool() });
export const TaskCreate = Task.omit({ id: true });
export const TaskPatch  = TaskCreate.partial();
```

**Verify:** grep for `z.strictObject(`/`z.object(` outside `lib/schemas/` (and outside `env.ts`) → zero inline route-local schemas for shared resources.

## Rule 8 — Client-side validation is UX only

`<form>` validation, React state checks, and disabled buttons are advisory: every Server Action is a public POST endpoint, and curl skips your form. The server-side parse from Rule 1 is the control; the client copy (same shared schema, via react-hook-form etc.) exists to give fast feedback. Validation failures return 400/422 with field-level issues only (`z.flattenError`) — never echo submitted values, stacks, or schema internals.

**Verify:** an integration test invokes each mutation directly with curl/`fetch` (no browser) using an invalid body → 400/422 whose body contains no submitted values or stack frames.

---

Next: [04 — Database & Row-Level Security](./04-database-rls.md) · [08 — Webhooks](./08-webhooks.md)
