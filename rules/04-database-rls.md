# 🗄️ Database & Row-Level Security

The database enforces tenancy itself: RLS on every table from the migration that creates it, parameterized queries only, and constraints as the last line that survives every app bug.

## TL;DR — the rules

1. Enable RLS in the same migration as `CREATE TABLE` — never as a follow-up.
2. Write four separate policies per table (SELECT/INSERT/UPDATE/DELETE); UPDATE gets both USING and WITH CHECK.
3. Wrap auth functions as `(select auth.uid())` and always add a `TO authenticated` clause; index every policy-filter column.
4. The service-role key lives in exactly one `import 'server-only'` module; never "fix" an RLS symptom with the service-role client.
5. SECURITY DEFINER functions pin `SET search_path = ''` and live in a private schema; views over RLS tables use `security_invoker = true`.
6. Every tenant table has `org_id NOT NULL`; app queries still filter by the caller's org — RLS is the backstop, not the only check.
7. Parameterized queries only — no string-built SQL, ever.
8. DB constraints (UNIQUE, CHECK, FK, NOT NULL) are the final integrity layer; check-then-insert is forbidden.
9. Counters/credits/quotas mutate in one atomic `UPDATE ... WHERE balance >= $x RETURNING` — never read-modify-write.
10. Test RLS in CI: `tests.rls_enabled('public')` + per-table pgTAP via `supabase test db`, splinter lints build-breaking.
11. Soft delete is a security state: every policy/view filters `deleted_at IS NULL`, user deletion revokes sessions in the same operation, uniqueness uses partial indexes, and secrets are hard-deleted — never soft-deleted.
12. Injection applies beyond SQL: query filters accept schema-validated scalars, never raw request objects — NoSQL operator injection (`{"$gt":""}`) and `$`-prefixed keys die at the boundary.

## Rule 1 — RLS in the same migration as CREATE TABLE

CVE-2025-48757: 170+ Lovable-built apps breached because tables shipped without RLS — a Supabase table without RLS is world-readable *and writable* via the anon key that ships in every browser bundle. The official Supabase starter ships zero policies and zero migrations; the follow-up migration that was supposed to add them never comes.

```sql
-- ❌ WRONG — "we'll add policies later"
create table public.documents (id uuid primary key, owner_id text not null, body text);

-- ✅ RIGHT — same migration: table, RLS, policies, index
create table public.documents (id uuid primary key default gen_random_uuid(),
  owner_id text not null, body text);
alter table public.documents enable row level security;
create policy "documents_select" on public.documents for select
  to authenticated using (owner_id = (select auth.uid()::text));
create index documents_owner_id_idx on public.documents (owner_id);
```

**Verify:** CI runs `select tablename from pg_tables where schemaname='public' and rowsecurity=false` → zero rows; `tests.rls_enabled('public')` passes in `supabase test db`.

## Rule 2 — Per-operation policies, WITH CHECK not just USING

Semantics (verified against Supabase docs + splinter): SELECT/DELETE use USING only; INSERT uses WITH CHECK only; **UPDATE needs both** — USING without WITH CHECK lets a user rewrite `owner_id`/`tenant_id` on any row they can see (ownership-transfer escalation). Missing DELETE policies fail silently (0 rows affected), and a later AI session "fixes" that with the service-role client.

```sql
-- ❌ WRONG — FOR ALL hides the per-operation semantics; no WITH CHECK on update path
create policy "docs_all" on public.documents for all using (owner_id = auth.uid()::text);

-- ✅ RIGHT — four policies; UPDATE pins ownership on both sides
create policy "docs_insert" on public.documents for insert
  to authenticated with check (owner_id = (select auth.uid()::text));
create policy "docs_update" on public.documents for update
  to authenticated using (owner_id = (select auth.uid()::text))
                   with check (owner_id = (select auth.uid()::text));
create policy "docs_delete" on public.documents for delete
  to authenticated using (owner_id = (select auth.uid()::text));
-- plus the SELECT policy from Rule 1; UPDATE ... RETURNING needs it too
```

**Verify:** pgTAP test — as user B, `UPDATE` user A's row and reassign `owner_id` to yourself: both must affect 0 rows.

## Rule 3 — `(select auth.uid())` and `TO authenticated`

Bare `auth.uid()` in a policy is re-evaluated per row (multi-second scans at 100K rows); the `(select ...)` wrapper makes Postgres cache it once per statement via initPlan (splinter lint `auth_rls_initplan`). Omitting the `TO` clause runs the policy for `anon` too — `auth.uid()` is NULL there, so `null = owner_id` filters *silently*: deny tests must assert **empty results, not errors**.

With Clerk as third-party auth, `auth.uid()` does not work at all: identity is `auth.jwt()->>'sub'`, active org `auth.jwt()->'o'->>'id'` — centralize in one STABLE helper used in both USING and WITH CHECK. Authorization data comes from `app_metadata`/custom claims, never `user_metadata` (any user edits that themselves via `supabase.auth.updateUser()` — splinter lint 0015).

**Verify:** splinter `auth_rls_initplan` and `rls_references_user_metadata` → zero findings; grep migrations for `create policy` lines lacking a `to` clause → zero.

## Rule 4 — Service-role key is quarantined, never a debugging tool

The service-role / `sb_secret_*` key carries BYPASSRLS. Threat-model row #15: when a query returns empty, AI sessions reach for the service-role client instead of fixing the policy. Debug in layers instead: error 42501 = missing GRANT; empty result = USING; rejected write = WITH CHECK.

```ts
// ❌ WRONG — "the query returned nothing, use the admin client"
const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);

// ✅ RIGHT — lib/db/admin.ts, the ONLY file that reads the key
import 'server-only';
import { env } from '@/env';
export function createAdminClient() {           // callers: webhooks, cron, admin jobs
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
}
// every callsite still scopes by org/user manually and writes an audit row
```

**Verify:** `grep -rln 'SERVICE_ROLE' src/ | grep -v 'db/admin'` → empty; after build, `grep -r 'sb_secret\|service_role' .next/static/` → empty.

## Rule 5 — SECURITY DEFINER and views

SECURITY DEFINER functions run as their owner (bypassing RLS) and inherit the caller's `search_path` — a writable schema earlier in the path means function hijack (splinter lint 0011). Views bypass RLS entirely by default (lint 0010).

```sql
-- ✅ RIGHT
create function private.is_org_member(check_org uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.memberships m
    where m.org_id = check_org and m.user_id = (select auth.jwt()->>'sub'));
$$;
revoke execute on function private.is_org_member from anon, authenticated; -- policy-internal
create view public.doc_summaries with (security_invoker = true) as
  select id, owner_id, left(body, 80) as preview from public.documents;
```

Use such helpers for membership lookups inside policies — it also avoids recursive-policy errors.

**Verify:** splinter lints 0010 (`security_definer_view`) and 0011 (`function_search_path_mutable`) → zero rows, build-breaking in CI.

## Rule 6 — Tenant isolation in both layers

IDOR/BOLA is OWASP API #1. RLS alone is not enough (a policy bug is one migration away), and app filters alone are not enough (one forgotten `.eq()` is one PR away). Every tenant table carries `org_id NOT NULL`; the app query scopes by the caller's org **from `auth()`, never from the request body**, and returns 404 on zero rows.

```ts
// ❌ WRONG — fetch-then-check, and orgId from the client
const doc = await db.query.documents.findFirst({ where: eq(documents.id, body.id) });
if (doc.orgId !== body.orgId) throw new Error('forbidden');

// ✅ RIGHT — ownership predicate in the WHERE clause; RLS is the backstop
const { orgId } = await auth();
const [doc] = await db.select().from(documents)
  .where(and(eq(documents.id, input.id), eq(documents.orgId, orgId)));
if (!doc) notFound();                            // 404, not 403 — don't confirm existence
```

**Verify:** seeded account B requests every one of account A's resource IDs → 404 on every endpoint (the two-account negative test, run in CI).

## Rule 7 — Parameterized queries only

Injection is OWASP A05:2025; string-built SQL is how it happens. Query builders and Supabase client filters parameterize for you — the ban is on template-literal SQL with interpolated values.

```ts
// ❌ WRONG
await client.query(`select * from documents where title = '${q}'`);

// ✅ RIGHT — placeholder, or the tagged-template form that parameterizes
await client.query('select * from documents where title = $1', [q]);
```

**Verify:** Semgrep rule flagging template literals containing `select|insert|update|delete` with `${` interpolation passed to a query function → zero findings.

## Rule 8 — Constraints are the final integrity layer

App-level checks race and get bypassed by admin scripts, webhooks, and future service-role code paths. UNIQUE, CHECK, FK, and NOT NULL hold regardless of which code path writes.

```sql
-- ✅ RIGHT
alter table public.credits add constraint credits_non_negative check (balance >= 0);
alter table public.fulfillments add constraint one_per_session unique (checkout_session_id);
-- claim idempotently, never check-then-insert:
insert into public.fulfillments (checkout_session_id, user_id) values ($1, $2)
  on conflict (checkout_session_id) do nothing;
```

**Verify:** pgTAP asserts each constraint exists (`has_check`, `col_is_unique`); a test inserting the same `checkout_session_id` twice succeeds exactly once.

## Rule 9 — Atomic updates kill read-modify-write races

PortSwigger's single-packet attack lands parallel requests in a ~1ms window: N concurrent "spend 10 credits" requests each read balance=10, each pass the check, each write. The fix is one statement where the check and the write are indivisible.

```ts
// ❌ WRONG — read-check-write: races under parallel requests
const { balance } = await getCredits(userId);
if (balance >= cost) await setCredits(userId, balance - cost);

// ✅ RIGHT — single atomic statement; zero rows returned = insufficient funds
const { rows } = await client.query(
  `update credits set balance = balance - $1
   where user_id = $2 and balance >= $1 returning balance`, [cost, userId]);
if (rows.length === 0) throw new PaymentRequiredError();
```

Pair with the `CHECK (balance >= 0)` constraint from Rule 8. On Supabase, wrap this in a SECURITY DEFINER RPC per Rule 5.

**Verify:** load test — 10 parallel spends exceeding the balance → total spent ≤ starting balance, exactly.

## Rule 10 — RLS tests in CI

AI-generated code fails by omission, and developers rate the result as *more* secure (Stanford, Perry et al.) — only machine gates catch the missing policy. `supabase test db` runs pgTAP from `supabase/tests/`; supabase-test-helpers provides `tests.create_supabase_user()`, `tests.authenticate_as()`, and the one-line schema tripwire `tests.rls_enabled('public')`.

```sql
-- ✅ RIGHT — supabase/tests/documents.test.sql (shape per basejump's suite)
begin; select plan(3);
select tests.rls_enabled('public');
select tests.create_supabase_user('alice'); select tests.create_supabase_user('bob');
select tests.authenticate_as('alice');
insert into public.documents (owner_id, body) values (tests.get_supabase_uid('alice')::text, 'x');
select tests.authenticate_as('bob');
select is_empty($$ select * from public.documents $$, 'bob sees no alice rows'); -- empty, not error
select is_empty($$ update public.documents set body='pwn' returning id $$, 'bob cannot write');
select * from finish(); rollback;
```

**Verify:** `supabase test db` runs on every migration PR; splinter Security Advisor lints (`rls_disabled_in_public`, `policy_exists_rls_disabled`, `security_definer_view`, `auth_users_exposed`, `function_search_path_mutable`, `rls_references_user_metadata`) run in CI as build-breaking.

## Rule 11 — Soft delete without resurrection

A `deleted_at` column the policies don't know about means "deleted" rows keep flowing into every query and view — and a soft-deleted *user* whose sessions survive is an account that keeps working after the admin removed it.

```sql
-- ❌ WRONG — policy ignores deletion; unique index blocks re-signup against a dead row
create policy docs_select on public.documents for select
  using (owner_id = (select auth.uid()::text));
create unique index users_email_idx on public.users (email);

-- ✅ RIGHT — deletion is part of every predicate; uniqueness only among the living
create policy docs_select on public.documents for select to authenticated
  using (owner_id = (select auth.uid()::text) and deleted_at is null);
create unique index users_email_live_idx on public.users (email)
  where deleted_at is null;
```

Deleting a user revokes their sessions and refresh tokens **in the same operation** (same transaction, or the immediately-following provider call) — never a later cleanup job. Secrets rows (API keys, OAuth tokens, TOTP seeds) are hard-deleted or crypto-shredded, never soft-deleted: a "deleted" credential in a dump is still a live credential. Restore is a privileged, audited transition — a service-role admin path with an audit row, not an UPDATE any client can reach.

**Verify:** pgTAP — soft-delete a row, SELECT as its owner → empty; delete a test user, replay their session cookie → 401; grep every policy and view on soft-delete tables for `deleted_at` → no predicate misses it.

## Rule 12 — Operator injection: filters take scalars, not request objects

**Why:** the NoSQL twin of string-built SQL. MongoDB-style stores interpret objects in filters: `db.users.findOne({ email, password })` with a JSON body of `{"email":{"$gt":""},"password":{"$gt":""}}` matches the first user — authentication bypassed without a single quote character. The same class hits any query builder that accepts request-shaped objects (Mongo/Mongoose, Firestore-style filters, `prisma.$queryRawUnsafe`, ORM `where` clauses spread from input).

```ts
// ❌ WRONG — request object flows into the filter
const user = await users.findOne({ email: req.body.email, password: req.body.password });

// ✅ RIGHT — strict schema guarantees scalars before the query is built
const { email } = loginSchema.parse(body);        // z.strictObject({ email: z.string().email(), ... })
const user = await users.findOne({ email: { $eq: email } });
```

The primary defense is [chapter 03](03-input-validation.md)'s strict parsing — `z.string()` rejects `{"$gt":""}` outright. Belt-and-suspenders for Mongo-family stores: strip `$`-prefixed keys and dots from any object that must remain dynamic (`mongo-sanitize`-style), pin values with `$eq`, and never spread parsed-but-open objects (`z.record`, `passthrough`) into a `where`. Prisma/Drizzle: raw-query escape hatches (`$queryRawUnsafe`, `sql.raw`) take no interpolated user input — same bar as Rule 7.

**Verify:** grep for `findOne({`/`find({`/`where:` sites fed by request-derived objects → every value passed is a schema-validated scalar; test login/search endpoints with `{"$gt":""}` and `{"$ne":null}` payloads → 400 from the schema, never a match.

---

Related: [03 — Input Validation](./03-input-validation.md) · [08 — Webhooks](./08-webhooks.md) · [11 — File Uploads & Storage](./11-file-uploads.md)
