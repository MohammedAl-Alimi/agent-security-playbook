# 📦 Supply Chain

Every dependency, lifecycle script, and CI action is code you run with your credentials — verify before install, freeze what you verified, and let machines re-check it on every PR (OWASP A03:2025).

## TL;DR — the rules

1. Verify every new package on npmjs.com/PyPI (real repo link, plausible downloads, age) before installing — LLMs hallucinate package names.
2. Commit lockfiles; CI installs only with `npm ci` / `pnpm install --frozen-lockfile` / locked pip.
3. Disable npm lifecycle scripts by default (`ignore-scripts=true`); allowlist the few that must build.
4. Run Dependabot/Renovate for patch cadence — npm, pip, AND github-actions ecosystems.
5. Gate CI on `npm audit` / `pnpm audit` (high+, prod deps) and pip-audit.
6. Pin every GitHub Action to a full 40-char commit SHA with a version comment.
7. Run SAST in CI: CodeQL (free on public repos) or Semgrep CE with framework rulesets, blocking on findings.
8. Review dependency-update diffs for typosquats and maintainer changes — a familiar-looking name is not verification.

## Rule 1 — Verify before install: slopsquatting is an active attack

**Why:** The USENIX '25 study measured LLMs hallucinating package names in 5.2–21.7% of code samples — and the hallucinations are *repeatable*, so attackers pre-register them (slopsquatting, arXiv 2605.17062). Failure mode #10 in the AI-codegen threat model: installing on the model's word.

```bash
# ❌ WRONG — the model suggested it, so it must exist
npm install fastapi-jwt-helper zod-strict-parse

# ✅ RIGHT — verify the exact name first, every time
npm view <name> repository.url downloads time.created   # real repo? plausible downloads? not 3 days old?
# open the repository.url and confirm it's the project the model described
# PyPI: check pypi.org/project/<name>/ — linked GitHub, release history, maintainers
```

Red flags: no repository link, repo that 404s or describes a different project, first publish within weeks, near-identical name to a popular package (`zood`, `requets`, `fastapi-utils` vs `fastapi_utils`).

**Verify:** PR checklist item + CI diff gate: any lockfile line adding a package published <30 days ago or with no registry repo link requires an explicit justification comment in the PR.

## Rule 2 — Lockfiles committed, CI installs frozen

**Why:** `npm install` in CI resolves ranges fresh — a malicious release published an hour ago walks straight into your build. Both 2025 npm mega-attacks (below) were delivered via *fresh versions* of trusted packages; a frozen lockfile plus a release-age delay neutralizes the window.

```yaml
# ❌ WRONG — CI resolves whatever is newest in-range
- run: npm install

# ✅ RIGHT — exactly the reviewed lockfile or fail
- run: npm ci                      # npm
- run: pnpm install --frozen-lockfile   # pnpm
- run: pip install -r requirements.txt --require-hashes  # python
```

pnpm additionally supports `minimumReleaseAge: 4320` (no version younger than 3 days), `blockExoticSubdeps: true`, and `trustPolicy: no-downgrade` in pnpm-workspace settings — adopt all three.

**Verify:** `git ls-files | grep -E 'package-lock.json|pnpm-lock.yaml'` non-empty; `grep -rn 'npm install\b' .github/workflows/` → zero hits (only `npm ci`).

## Rule 3 — Lifecycle scripts are the payload vector: disable by default

**Why:** September 2025's 'qix' phishing compromised chalk/debug (~2.6B weekly downloads) with a wallet-drainer, and the Shai-Hulud worm hit 500+ packages with `postinstall` payloads that stole npm/GitHub/cloud credentials and self-propagated. Both executed at install time via lifecycle scripts.

```ini
# ✅ RIGHT — .npmrc committed at repo root
ignore-scripts=true
save-exact=true
```

```yaml
# ✅ pnpm-workspace.yaml — explicit build allowlist, never dangerouslyAllowAllBuilds
onlyBuiltDependencies:
  - sharp
  - esbuild
```

Some packages (sharp, esbuild, bcrypt) genuinely need install scripts — allowlist those exact names after checking what the script does; everything else stays inert.

**Verify:** `grep -q 'ignore-scripts=true' .npmrc` in CI; `pnpm config get dangerouslyAllowAllBuilds` is not true; fresh clone + install runs zero unexpected postinstalls.

## Rule 4 — Automated patch cadence: Dependabot/Renovate on three ecosystems

**Why:** Known-vuln dependencies are the boring half of A03:2025 — the fix is cadence, not heroics. The commonly-missed ecosystem is `github-actions`: your workflow deps are dependencies too, and Dependabot is what keeps SHA pins (Rule 6) current without manual archaeology.

```yaml
# ✅ RIGHT — .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule: { interval: weekly }
    groups: { minor-and-patch: { update-types: [minor, patch] } }
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
  - package-ecosystem: pip
    directory: /
    schedule: { interval: weekly }
```

**Verify:** `.github/dependabot.yml` exists and lists `github-actions`; the repo has merged a Dependabot PR in the last 30 days (staleness alarm otherwise).

## Rule 5 — Audit gate in CI

**Why:** An advisory published after you installed is invisible without a recurring check. Gate on production deps at high+ so the signal stays actionable instead of drowning in dev-dep noise.

```yaml
# ✅ RIGHT — blocking audit step
- run: npm audit --omit=dev --audit-level=high    # or: pnpm audit --prod --audit-level high
- run: pip-audit -r requirements.txt              # python services
```

**Verify:** the audit step has no `|| true` / `continue-on-error: true`; introduce a known-vulnerable pin on a test branch → CI fails.

## Rule 6 — Pin GitHub Actions by full SHA

**Why:** March 2025: tj-actions/changed-files had **every version tag repointed** at a malicious commit that dumped CI secrets from 23,000+ repos. Tags are mutable pointers; a 40-char SHA is content-addressed. SHA-pinned users were unaffected.

```yaml
# ❌ WRONG — tag can be repointed at any time
- uses: actions/checkout@v5

# ✅ RIGHT — immutable SHA, human-readable comment, least-privilege token
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
```

Use `pinact run` to rewrite existing workflows; Dependabot bumps SHA and comment together.

**Verify:** `grep -E 'uses:.*@(v[0-9]|main|master)' .github/workflows/*` → empty; `pinact run --check` passes in CI; every workflow has a top-level `permissions:` block.

## Rule 7 — SAST in CI, blocking

**Why:** AI-generated code fails by omission (missing authz, missing validation) — exactly the class a rules engine catches mechanically that reviewers skim past. Veracode 2025: AI introduces vulnerabilities in 45% of coding tasks; reviewers using AI also trust it more (Stanford), so the gate must be a machine.

```yaml
# ✅ RIGHT — public repo: enable CodeQL default setup (free) in repo settings.
# Private repo: Semgrep CE on PRs, blocking:
- uses: actions/checkout@<full-sha> # v5.0.0
- run: pipx run semgrep scan --config p/typescript --config p/nextjs --config p/react \
       --config .semgrep/ --error
```

Keep a repo-local `.semgrep/` directory: every incident and review finding becomes a permanent rule — that directory is the institutional memory.

**Verify:** SAST job is a required status check on the default branch; seeding a known-bad pattern (e.g., `dangerouslySetInnerHTML` on tainted data) on a test branch fails CI.

## Rule 8 — Review dependency diffs like code

**Why:** A Dependabot PR titled "bump lodash 4.17.20 → 4.17.21" that actually swaps in `lodash-es-utils` — or a lockfile edit smuggled into a feature PR — is the last unwatched door. Typosquats and resolved-URL changes are visible only in the lockfile diff.

```text
✅ RIGHT — on every PR that touches a lockfile, check:
- names byte-for-byte (lodash vs lodash-utils vs 1odash)
- resolved URLs still point at registry.npmjs.org / pypi.org, not a lookalike host
- no new packages you didn't ask for; no integrity-hash-only changes on unchanged versions
- for major bumps: skim the release diff on the repo, not just the changelog
```

**Verify:** CODEOWNERS routes `package.json`, lockfiles, and `.github/workflows/**` to a designated reviewer; branch protection requires that review before merge.

---

Related: [05 — Secrets & Env](05-secrets-and-env.md) (gitleaks/TruffleHog CI, push protection — what stolen CI creds are after) · [13 — SSRF & LLM](13-ssrf-and-llm.md) (why model suggestions are untrusted input, packages included).
