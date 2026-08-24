# 🏗️ Deployment & Infrastructure

Harden the container, the DNS records, the preview URLs, and the environment split — the layers below the app are where clean application code still gets owned.

## TL;DR — the rules

1. Containers: multi-stage build, digest-pinned distroless base, non-root `USER`, no secrets in `ARG`/`ENV`/layers, `.dockerignore` covering `.env*`.
2. Gate images in CI: hadolint on the Dockerfile, Trivy scan failing on HIGH/CRITICAL, Checkov/`trivy config` on IaC.
3. DNS: remove records BEFORE deleting the project they point at; keep a DNS inventory in-repo; audit CNAMEs periodically; host-only cookies.
4. Vercel: Standard Deployment Protection on every project — previews and `*.vercel.app` URLs require auth; test the interstitial in ch15.
5. One platform instance per environment: Clerk production instance, Supabase project per env; boot assertion fails prod startup on `_test_` keys.
6. Prod config: FastAPI `docs_url`/`openapi_url` off, `debug=False` asserted, no public source maps — pre-deploy curl proves it.
7. Self-hosted TLS: Mozilla intermediate profile, TLS 1.2+ AEAD only, ACME auto-renew, verified by testssl.sh.
8. Serve `/.well-known/security.txt` (RFC 9116) from [templates/security.txt](../templates/security.txt).

## Rule 1 — Containers: distroless, digest-pinned, non-root, secret-free layers

A single-stage image built from `node:latest` runs as root, ships your compiler toolchain and `.env` into production, and changes under you on every pull. Secrets passed via `ARG`/`ENV` persist in image history (`docker history` shows them) even if a later layer "deletes" them.

```dockerfile
# ❌ WRONG — mutable tag, root, .env copied in, secret baked into a layer
FROM node:latest
COPY . .
ARG DATABASE_URL
RUN npm run build

# ✅ RIGHT — multi-stage, digest-pinned distroless, non-root, runtime-only secrets
FROM node:22-slim@sha256:<digest> AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:<digest>
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
USER nonroot
CMD ["dist/server.js"]
# secrets arrive at runtime from the platform env (05-secrets-and-env.md), never at build time
```

`.dockerignore` must cover `.env*`, `.git`, `node_modules`, and key material — `COPY . .` in the build stage copies whatever isn't ignored into a layer forever. Run with `--security-opt no-new-privileges` (or the orchestrator equivalent).

**Verify:** `docker history --no-trunc $IMG | grep -Ei 'secret|password|key|token'` → empty; `docker inspect $IMG --format '{{.Config.User}}'` → non-root; grep `.dockerignore` for `.env` → present.

## Rule 2 — CI gates: hadolint, Trivy, Checkov

A hardened Dockerfile decays the first time a future session "temporarily" adds `USER root` to debug. The linters make the decay a red build instead of a silent regression.

```yaml
# ✅ RIGHT — .github/workflows/container.yml (fail the build, don't just report)
- uses: hadolint/hadolint-action@v3
  with: { dockerfile: Dockerfile }
- uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.IMAGE }}
    severity: HIGH,CRITICAL
    exit-code: '1'          # ❌ WRONG: exit-code '0' — a scan that can't fail is decoration
- run: trivy config --exit-code 1 --severity HIGH,CRITICAL .   # or checkov -d . for IaC
```

**Verify:** intentionally add `USER root` on a branch → CI fails; the Trivy step has `exit-code: '1'`, not report-only.

## Rule 3 — DNS hygiene: records die before projects; inventory in-repo

Subdomain takeover is an ordering bug: delete the Vercel project first and `app.example.com` still CNAMEs to `cname.vercel-dns.com` — anyone who claims that domain on Vercel now serves content on your subdomain, inherits your users' trust, and (if your cookies are domain-scoped) reads their sessions. The polyfill.io incident showed the same shape at the supply-chain layer: a name everyone still referenced changed owners and turned hostile.

```text
❌ WRONG order: delete Vercel project → "clean up DNS later" (the takeover window)
✅ RIGHT order: remove/repoint the DNS record → wait for TTL → delete the project
```

```yaml
# ✅ RIGHT — dns-inventory.yml, committed next to the code that owns it
- host: app.example.com
  type: CNAME
  target: cname.vercel-dns.com
  owner: vercel:project=app        # deleting this project requires deleting this line first
- host: status.example.com
  type: CNAME
  target: example.statuspage.io    # third-party — audit quarterly against can-i-take-over-xyz
```

Cookies: issue them host-only (`__Host-` prefix, no `Domain=` attribute — [01 — Authentication](./01-authentication.md)) so a lost subdomain can never read the parent domain's sessions.

**Verify:** CI script resolves every CNAME in `dns-inventory.yml` and fails on NXDOMAIN/unclaimed targets; grep session-cookie call sites for `domain:` → zero.

## Rule 4 — Vercel Deployment Protection on every preview

Every push creates a preview deployment with a guessable-shape `*.vercel.app` URL running your real code — often against real preview env vars. Unprotected previews are an unauthenticated mirror of your app that search engines and scrapers do find. Standard Protection puts Vercel Authentication in front of previews and `*.vercel.app` production aliases; on older projects, confirm git-branch alias URLs are covered too.

```jsonc
// ❌ WRONG — protection disabled so "the client can click the link"
// (share access via shareable links instead of unprotecting the project)

// ✅ RIGHT — assert protection from CI (Vercel API)
// GET https://api.vercel.com/v9/projects/$PROJECT → expect:
{ "ssoProtection": { "deploymentType": "prod_deployment_urls_and_all_previews" } }
```

CI and E2E reach protected previews with the Protection Bypass for Automation secret — which is a credential, handled per [05 — Secrets & Env](./05-secrets-and-env.md), never pasted into client code or shared chats.

**Verify:** ch15 test fetches the latest preview URL unauthenticated → Vercel auth interstitial (401/redirect), not your app; API check above runs in CI for every project.

## Rule 5 — One platform instance per environment; prod refuses test keys

Sharing one Clerk dev instance or one Supabase project across dev and prod means a test key leak is a prod breach and every migration experiment runs against customer data. Clerk dev instances (`pk_test_`) have relaxed security by design and must never serve production traffic; Supabase gets a project per environment with migrations flowing dev → staging → prod via CI, and staging holds anonymized data only.

```ts
// ❌ WRONG — prod silently boots against dev/test backends
export const env = { CLERK_KEY: process.env.CLERK_PUBLISHABLE_KEY! };

// ✅ RIGHT — boot-time assertion: prod with test keys must not start
export function assertProdEnv() {
  if (process.env.VERCEL_ENV !== 'production') return;
  const violations = [
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY?.startsWith('pk_test_') && 'Clerk test instance',
    process.env.STRIPE_SECRET_KEY?.includes('_test_') && 'Stripe test mode',
    process.env.SUPABASE_URL?.includes(DEV_PROJECT_REF) && 'Supabase dev project',
  ].filter(Boolean);
  if (violations.length) throw new Error(`prod boot refused: ${violations.join(', ')}`);
}
```

Call it at module scope of the server entrypoint so a misconfigured deploy fails health checks instead of serving.

**Verify:** deploy to a prod-flagged environment with a `pk_test_` key → boot fails; grep prod env-var config for `_test_`/dev project refs → zero.

## Rule 6 — Prod config: no docs endpoints, no debug, no source maps

Default FastAPI serves `/docs` and `/openapi.json` to the world — a free, always-current map of every route, parameter, and schema for attackers. Debug modes leak stack traces and env; public source maps hand over your original server-adjacent source and comments.

```python
# ❌ WRONG — interactive API docs and schema public in prod
app = FastAPI()

# ✅ RIGHT — off in prod (or auth-gated), asserted at boot
IS_PROD = settings.ENV == "production"
app = FastAPI(
    docs_url=None if IS_PROD else "/docs",
    redoc_url=None if IS_PROD else "/redoc",
    openapi_url=None if IS_PROD else "/openapi.json",
)
assert not (IS_PROD and settings.DEBUG), "DEBUG=True in production"
```

Next.js: don't set `productionBrowserSourceMaps: true` unless sources are meant to be public, and never expose server source maps. Seed/debug routes (`/api/seed`, `/api/debug`) must be excluded from prod builds, not merely hidden. Log files are never web-reachable: nothing under the served root writes `*.log`, and log/debug viewer routes (`/logs`, `/debug/log`) don't exist in prod — logs go to the platform's log drain, not to files an URL can reach.

**Verify:** pre-deploy check — `curl -s -o /dev/null -w '%{http_code}' https://$HOST/docs /openapi.json /_next/static/**/*.map /logs /app.log /debug.log` → 401/404 for each; grep for `debug=True`/`DEBUG=true` in prod config → zero; grep for file-writing log transports targeting the public/static directory → zero.

## Rule 7 — TLS for self-hosted: Mozilla intermediate, ACME, testssl.sh

Vercel manages TLS for you; a self-hosted FastAPI box behind your own nginx/Caddy is your job. Hand-written TLS config rots — pin it to the Mozilla intermediate profile (TLS 1.2+ with AEAD suites only, no CBC, no TLS 1.0/1.1), generated from ssl-config.mozilla.org rather than from memory, with ACME (certbot/Caddy) auto-renewal so expiry can't take you down or tempt a "temporary" plaintext fallback.

```nginx
# ✅ RIGHT — nginx, Mozilla intermediate (generate at ssl-config.mozilla.org)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
# ❌ WRONG — ssl_protocols TLSv1 TLSv1.1 TLSv1.2; ssl_ciphers HIGH:!aNULL;
```

HSTS on top is [10 — Headers, CSP & CORS](./10-headers-csp-cors.md); this rule is the transport under it.

**Verify:** `testssl.sh --severity HIGH https://$HOST` in ch15's pipeline → no HIGH/CRITICAL findings; protocol scan shows TLS 1.0/1.1 disabled.

## Rule 8 — Publish security.txt

RFC 9116 gives researchers a machine-readable path to report the vulnerability to you instead of tweeting it. It's one static file at `/.well-known/security.txt` — fill in [templates/security.txt](../templates/security.txt) and serve it from `public/.well-known/`.

```text
✅ RIGHT — public/.well-known/security.txt (from the template)
Contact: mailto:security@example.com
Expires: 2027-08-21T00:00:00Z
Canonical: https://example.com/.well-known/security.txt
```

Keep `Expires` within a year and calendar the renewal — an expired file signals an unmonitored inbox.

**Verify:** `curl -s https://$HOST/.well-known/security.txt` → 200 with `Contact:` and a future `Expires:`; CI warns when `Expires` is < 30 days away.

---

Previous: [24 — Realtime & Client-Side Channels](./24-realtime-channels.md) · Template: [templates/security.txt](../templates/security.txt)
