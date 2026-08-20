# 🛡️ Authorization & RBAC

Knowing *who* is calling ([authentication](01-authentication.md)) says nothing about *what* they may touch. Missing object-level checks are OWASP API Security #1 and the most common defect in AI-generated apps.

## TL;DR — the rules

1. Never conflate "is logged in" with "may do this" — every operation has an explicit permission decision.
2. Every query that takes an object ID also filters by the caller's identity in the WHERE clause; zero rows → 404.
3. All permission decisions go through one policy module — a single `can(user, action, resource)` entry point.
4. Roles and identity come from the server session only; `role`/`orgId`/`userId` in a request body is an attack.
5. Every tenant-owned table carries a non-null `tenant_id`, filtered in app queries AND enforced by RLS as backstop.
6. Deny by default: no matching policy, thrown error, or missing role → denied, never allowed.
7. Any diff that widens permissions requires explicit human approval — never a debugging tactic.

## Rule 1 — Authentication ≠ authorization

**Why:** The signature vibe-coding failure (research corpus §2 row 5): "is logged in" gets checked, "owns row :id" never does. Escape.tech's scan of 5,600 vibe-coded apps and Symbiotic's 98%-flawed sample of 1,072 both found this class dominant. A valid session is the *start* of the check, not the check.

```ts
// ❌ WRONG — authenticated, therefore trusted
const { userId } = await auth();
if (!userId) return unauthorized();
const doc = await db.document.findUnique({ where: { id: params.id } }); // anyone's doc

// ✅ RIGHT — authenticated, then authorized for THIS resource
const { userId } = await auth();
if (!userId) return unauthorized();
const doc = await db.document.findFirst({
  where: { id: params.id, ownerId: userId }, // ownership is part of the query
});
if (!doc) return notFound();
```

**Verify:** two-account test — seed accounts A and B, have B request every one of A's resource IDs across all endpoints → 404/403 on each; this suite is a merge blocker for every multi-tenant feature.

## Rule 2 — IDOR/BOLA: scope every object query, 404 on zero rows

**Why:** Broken Object Level Authorization is OWASP API1:2023. Fetch-then-check ("load the row, then compare owner") leaks existence via error shape and timing, and one forgotten `if` is a full breach. The scoped query makes the database enforce ownership atomically; returning 404 (not 403) refuses to confirm the object exists. Unguessable UUIDs are defense-in-depth only — never the control.

```ts
// ❌ WRONG — fetch-then-check
const inv = await db.invoice.findUnique({ where: { id } });
if (inv.orgId !== orgId) return forbidden(); // confirms existence; easy to forget

// ✅ RIGHT — ownership predicate inside the query
const inv = await db.invoice.findFirst({ where: { id, orgId } });
if (!inv) return notFound(); // same answer for "absent" and "not yours"
```

Python/FastAPI (chained-dependency pattern from zhanymkanov/fastapi-best-practices):

```python
async def valid_owned_invoice(id: UUID, user=Depends(get_current_user)) -> Invoice:
    inv = await db.fetch_one(
        "SELECT * FROM invoices WHERE id = :id AND org_id = :org", {"id": id, "org": user.org_id})
    if not inv:
        raise HTTPException(404)
    return inv  # routes depend on this; unscoped lookups have nowhere to hide
```

**Verify:** grep the data layer for `findUnique`/`SELECT ... WHERE id =` calls whose predicate lacks a caller-identity column → zero unjustified hits; cross-tenant test from Rule 1 passes.

## Rule 3 — One policy module, not scattered checks

**Why:** Twenty inline `if (user.role === 'admin')` checks drift, and an AI session editing one file cannot see the other nineteen. A single `can()` entry point (hand-rolled `lib/authz.ts`, or CASL's `defineAbilityFor` when UI and server share rules) makes every decision greppable, testable, and consistent. Don't over-engineer: no Cerbos/OpenFGA-style policy engine for a two-role app.

```ts
// ❌ WRONG — role literals sprinkled through handlers
if (user.role === 'admin' || (user.role === 'editor' && doc.ownerId === user.id)) { ... }

// ✅ RIGHT — lib/authz.ts is the only file that knows the rules
type Action = 'read' | 'update' | 'delete' | 'invite';
export function can(user: SessionUser, action: Action, resource: Resource): boolean {
  const policy = POLICIES[resource.kind]?.[action];
  return policy ? policy(user, resource) : false; // unknown → deny (Rule 6)
}
// handlers everywhere:
if (!can(user, 'delete', doc)) return notFound();
```

**Verify:** grep for role-string literals (`'admin'`, `'owner'`, `role ===`) outside `lib/authz.ts` → zero; unit-test the policy table directly with a role × action matrix.

## Rule 4 — Roles come from the session, never from the request

**Why:** Mass assignment (research corpus §2 row 6): schemas that pass unknown keys through (`.passthrough()`, Pydantic `extra='ignore'` spread into an update) let a client POST `{"role":"admin"}` or swap `orgId`. Zod's default silently *strips* — safer, but the correct posture is loud rejection plus never accepting identity fields at all.

```ts
// ❌ WRONG — client controls its own privileges
const body = await req.json();
await db.user.update({ where: { id: body.userId }, data: { ...body } });

// ✅ RIGHT — strict schema; identity derived server-side only
const Input = z.strictObject({ displayName: z.string().max(80) }); // no role/userId/orgId
const input = Input.parse(await req.json());
const { userId } = await auth();
await db.user.update({ where: { id: userId }, data: input });
```

Python: body models use `ConfigDict(extra='forbid')`; never `Model(**request_json)` into an ORM write.

**Verify:** grep input schemas for `userId|orgId|role|isAdmin|plan` → every hit has a written justification; test POSTs `{"role":"admin"}` to every mutation → 400 or ignored, and the role is unchanged.

## Rule 5 — Multi-tenant isolation: tenant_id everywhere + RLS backstop

**Why:** CVE-2025-48757 breached 170+ Lovable-built apps whose tables had no row-level security — world-readable via the anon key shipped in every browser bundle. Defense in depth: app queries scope by `orgId` from the session (Rule 2), and the database independently enforces the same predicate, so one forgotten filter is contained.

```sql
-- ❌ WRONG — table trusts the app layer completely
CREATE TABLE documents (id uuid PRIMARY KEY, body text);

-- ✅ RIGHT — same migration: tenant column, RLS, per-operation policies
CREATE TABLE documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id text NOT NULL,
  body text
);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON documents FOR SELECT TO authenticated
  USING (org_id = (select auth.jwt()->'o'->>'id'));
CREATE POLICY docs_update ON documents FOR UPDATE TO authenticated
  USING (org_id = (select auth.jwt()->'o'->>'id'))
  WITH CHECK (org_id = (select auth.jwt()->'o'->>'id')); -- both, or users re-home rows
```

UPDATE needs USING **and** WITH CHECK; keep explicit `.eq('org_id', orgId)` in app queries too. Derive tenant claims from `app_metadata`/custom claims — never `user_metadata`, which users edit themselves.

**Verify:** `tests.rls_enabled('public')` passes in `supabase test db` (or equivalent: `SELECT tablename FROM pg_tables WHERE schemaname='public' AND rowsecurity=false` → zero rows); pgTAP asserts a non-member sees **empty results** on every tenant table.

## Rule 6 — Deny by default

**Why:** OWASP A10:2025 (Mishandling of Exceptional Conditions): AI-generated catch blocks routinely convert failures into success paths. An unknown action, missing membership, null org, or thrown lookup error must all land on "denied" — the fail-open branch is the vulnerability.

```ts
// ❌ WRONG — error in the check becomes access
let allowed = true;
try { allowed = await checkMembership(userId, orgId); } catch { /* shrug */ }

// ✅ RIGHT — no policy match or any failure → denied
try {
  if (!can(user, action, resource)) return notFound();
} catch (e) {
  log.error({ e, requestId }, 'authz_fail');
  return notFound(); // fail closed
}
```

**Verify:** unit test: `can()` with an unknown action/resource kind returns `false`; force the membership lookup to throw in a test → response is 404/403, never 200.

## Rule 7 — Permission-widening diffs require human approval

**Why:** Recurring AI debugging behavior (research corpus §2 row 15): hitting a permissions error, the model "fixes" it with `USING (true)`, disabling RLS, commenting out the auth check, or switching to the service-role client. A permissions error means the policy is wrong or the caller is — fix that, never remove the control.

```sql
-- ❌ WRONG — "fixed" the 42501 error by removing the security
ALTER TABLE documents DISABLE ROW LEVEL SECURITY;
-- or: CREATE POLICY p ON documents USING (true);
```

```ts
// ✅ RIGHT — agents stop and escalate instead
// Debug in layers: 42501 = missing GRANT; empty result = USING; rejected write = WITH CHECK.
// Any diff that deletes an auth check, widens a policy/CORS, or swaps in the
// service-role client ships only with an explicit human sign-off in the PR.
```

**Verify:** CI grep on the diff for `USING (true)`, `DISABLE ROW LEVEL SECURITY`, `service_role`, removed `auth(`/`can(` lines → any hit blocks merge pending a human-approval label.
