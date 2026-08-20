# 📁 File Uploads & Storage

Every uploaded byte is attacker-controlled: validate content not declarations, store under server-generated keys in private buckets, and never serve raw uploads from your own origin.

## TL;DR — the rules

1. Validate file type by magic bytes on the server — never by extension or client Content-Type; undetectable = reject.
2. Enforce size limits server-side (bucket `fileSizeLimit`, streamed byte counters) — the client's word counts for nothing.
3. Server generates the storage key (`${userId}/${uuid}.${ext}`); user filenames are display-only DB data — never path input.
4. Buckets are private by default; access goes through short-TTL signed URLs after an ownership check.
5. Storage gets its own RLS: owner-scoped `storage.objects` policies per operation, committed as migrations.
6. Re-encode images (sharp/Pillow) to destroy embedded payloads and strip EXIF.
7. Never serve user uploads from your app origin without `Content-Disposition: attachment` / CSP sandbox — SVG/HTML uploads are stored XSS.
8. Block dangerous types (SVG, HTML, executables) unless sanitized by transcoding; wildcard `image/*` on a public bucket is banned.

## Rule 1 — Magic bytes, not extensions or Content-Type

`file.type` / `Content-Type` / the filename extension are all client-supplied declarations — Supabase's `allowedMimeTypes` checks only the *declared* type, inferred from the client's filename. The boilerplate survey found ZERO of six "production-ready" starters validate uploads at all.

```ts
// ❌ WRONG — trusts the client's declaration
if (!file.type.startsWith('image/')) return bad();

// ✅ RIGHT — sniff the actual bytes
import { fileTypeFromBuffer } from 'file-type'; // v22, ESM-only
const buf = Buffer.from(await file.arrayBuffer());
const detected = await fileTypeFromBuffer(buf);
const ALLOWED = new Set(['image/jpeg', 'image/png', 'image/webp']);
if (!detected || !ALLOWED.has(detected.mime)) return bad(); // undetectable (SVG/text/HTML) = reject
const ext = detected.ext; // extension from the DETECTION, never from file.name
```

```python
# ✅ RIGHT — FastAPI: python-magic on the head of the stream (needs system libmagic)
head = await file.read(2048); await file.seek(0)
if magic.from_buffer(head, mime=True) not in ALLOWED:
    raise HTTPException(415)
```

Note `file-type` cannot detect text formats — that is a feature: SVG/HTML/CSV come back undetectable and get rejected on the binary path, handled explicitly elsewhere if needed.

**Verify:** test uploads a `.jpg`-named HTML file with `Content-Type: image/jpeg` → 415; grep upload handlers for `file.type`/`content_type` used in an allow decision → zero.

## Rule 2 — Size limits enforced server-side

FastAPI's `UploadFile` has **no size limit by default**, and `await file.read()` buffers whatever arrives — a decompression-bomb-sized body is a self-DoS. Vercel adds hard caps that make proxying a trap: 4.5 MB function body limit, 1 MB Server Action default.

```ts
// ✅ RIGHT — bucket-level cap at creation (defense in depth with the endpoint check)
await supabase.storage.createBucket('user-docs', {
  public: false, fileSizeLimit: '10MB',
  allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp'], // declared-type prefilter only
});
```

```python
# ✅ RIGHT — stream with a byte counter; never bare await file.read()
size = 0
with open(dest, 'wb') as out:
    while chunk := await file.read(64 * 1024):
        size += len(chunk)
        if size > MAX_BYTES:
            raise HTTPException(413)
        out.write(chunk)
```

Anything larger than ~1 MB goes direct-to-storage: an authenticated, rate-limited endpoint mints `createSignedUploadUrl(path)` (2h token) for a **server-built** path — never a client-supplied one.

**Verify:** upload of `MAX_BYTES + 1` → 413/400 at the server, asserted in a test that bypasses any client-side check; CI SQL asserts no bucket lacks `fileSizeLimit`.

## Rule 3 — Randomized server-generated keys

A user-supplied filename is path input: `../../avatars/admin.png` overwrites another user's object (path traversal), and predictable names enable enumeration and squatting. `upsert: true` with a client-influenced path is an overwrite primitive.

```ts
// ❌ WRONG — client controls the key
await supabase.storage.from('avatars').upload(file.name, file, { upsert: true });

// ✅ RIGHT — server builds the whole path; original name is display-only metadata
const { userId } = await auth();
const key = `${userId}/${crypto.randomUUID()}.${ext}`; // ext from Rule 1's detection
await supabase.storage.from('avatars').upload(key, sanitized, { contentType: detected.mime });
await db.insert(files).values({ key, ownerId: userId, displayName: file.name.slice(0, 255) });
```

**Verify:** grep upload code for `file.name`/`filename` inside any storage path expression → zero (a custom Semgrep rule; none exist in the registry for Supabase Storage — write it).

## Rule 4 — Private buckets + short-TTL signed URLs

A bucket created `public: true` serves every object with **no policy check on reads** — the storage equivalent of a table without RLS (threat-model row #19; same class as CVE-2025-48757). Default to private and mint access per request.

```ts
// ❌ WRONG — public bucket "so the img tag works"
await supabase.storage.createBucket('user-docs', { public: true });

// ✅ RIGHT — ownership check, then a short-lived signed URL
const { userId } = await auth();
const file = await db.query.files.findFirst(
  { where: and(eq(files.id, input.id), eq(files.ownerId, userId)) }); // scoped query, 404 on miss
if (!file) notFound();
const { data } = await supabase.storage.from('user-docs')
  .createSignedUrl(file.key, 60); // seconds — TTL matches one page view, not a season
```

**Verify:** CI SQL asserts the public-bucket list equals a committed allowlist; fetching a private object's raw storage URL without a token → 400/403.

## Rule 5 — Storage RLS: owner-scoped path policies

`storage.objects` has its own RLS surface; the dashboard-clicked policy that never made it into a migration is how the next environment ships open. Scope every policy to `bucket_id` and pin the first path segment to the caller. With Clerk, `auth.uid()` cannot represent Clerk IDs — compare against `(select auth.jwt()->>'sub')`; use `owner_id` (text), never the deprecated `owner` column.

```sql
-- ✅ RIGHT — committed migration; upsert needs INSERT + SELECT + UPDATE
create policy "avatars_insert_own" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.jwt()->>'sub'));
create policy "avatars_select_own" on storage.objects for select to authenticated
  using (bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.jwt()->>'sub'));
```

Service-role uploads bypass all storage RLS — such routes must themselves enforce caller-userId == first path segment and run the content checks.

**Verify:** pgTAP — user B uploading to and listing `userA/...` paths both fail (empty, not error); every private bucket has committed policies (no dashboard-only policies: `supabase db diff` is clean).

## Rule 6 — Re-encode images: strip payloads and EXIF

An uploaded "image" can be a polyglot (valid JPEG + valid script/archive), carry decompression bombs, or leak the uploader's GPS position via EXIF. Transcoding through sharp destroys all three at once.

```ts
// ✅ RIGHT — sanitize-by-transcoding before storage
import sharp from 'sharp';
const sanitized = await sharp(buf, { limitInputPixels: 268402689 }) // caps decompression bombs
  .rotate()          // bakes in EXIF orientation…
  .webp()            // …then re-encoding drops EXIF (GPS included) and any polyglot payload
  .toBuffer();
await supabase.storage.from('avatars').upload(key, sanitized, { contentType: 'image/webp' });
```

Python: Pillow open → `Image.new` copy → save to a fresh buffer achieves the same. Anything you cannot re-encode (PDF, ZIP) is stored as-is but served per Rule 7 with `?download` forced.

**Verify:** test uploads a GPS-tagged JPEG and a JPEG/HTML polyglot → the stored object has no EXIF block and no `<script` bytes.

## Rule 7 — Never serve raw uploads from your app origin

A stored SVG or HTML file served inline from your domain executes in your origin: session cookies, localStorage, same-site fetches — stored XSS with persistence. The supabase.co origin split protects you **only if you never proxy raw uploaded bytes** through your own routes.

```ts
// ❌ WRONG — proxying raw bytes onto the app origin, browser may sniff and render
export async function GET(req: Request) {
  const blob = await supabase.storage.from('docs').download(key);
  return new Response(blob); // inline, sniffable, same-origin
}

// ✅ RIGHT — prefer redirecting to a signed URL on the storage origin (Rule 4);
// if you MUST proxy, neutralize rendering:
return new Response(blob.stream(), { headers: {
  'Content-Type': 'application/octet-stream',
  'Content-Disposition': `attachment; filename="download"`,
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "sandbox; default-src 'none'",
}});
```

For Supabase-served files that were not re-encoded, force `?download` on the signed URL.

**Verify:** Playwright loads an uploaded `<svg onload=...>` via every serving path → no script executes (assert no dialog/console beacon); header-assertion test on the proxy route checks `Content-Disposition` + `nosniff`.

## Rule 8 — Block dangerous types unless sanitized

SVG is XML with script support; HTML is HTML; executables and archives are malware carriers. None belong on a public bucket, and `image/*` wildcards quietly admit `image/svg+xml`.

```ts
// ❌ WRONG — wildcard admits SVG onto a public bucket
allowedMimeTypes: ['image/*']

// ✅ RIGHT — explicit allowlist, no SVG/HTML; the same list drives Rule 1's byte check
allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp']
```

If the product genuinely needs SVG, sanitize (DOMPurify server-side profile) or rasterize via sharp, and still serve it per Rule 7. Executables and unknown binaries: reject, or store quarantined pending an AV scan (e.g. ClamAV) — never publicly retrievable pre-scan.

**Verify:** grep bucket-creation code and migrations for `svg`, `text/html`, and `image/*` in any allowlist → zero on public buckets; upload tests for `.svg`, `.html`, `.exe` all → 415.

---

Related: [03 — Input Validation](./03-input-validation.md) · [04 — Database & RLS](./04-database-rls.md)
