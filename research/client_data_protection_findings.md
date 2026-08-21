# Client Data Protection — Research Findings

Research pass (2026-08-21) behind [chapter 17](../rules/17-client-data-protection.md): how client/customer data leaks into git and everywhere else, and the verified defenses. Two researchers, all URLs confirmed live at research time.

---

## Part A — Leaks into git repositories

### Documented incidents (customer data, not just credentials)

- **MedData patient records (2019–2021):** employee uploaded confidential patient records (names, SSNs, diagnoses) to public GitHub; data was replicated into the GitHub Arctic Code Vault — beyond anyone's deletion reach. [BleepingComputer](https://www.bleepingcomputer.com/news/security/github-arctic-vault-likely-contains-leaked-meddata-patient-records/)
- **Jelle Ursem research (2020):** ≥9 US healthcare entities leaking PHI of ~150,000–200,000 patients via public GitHub, found with trivial searches. [HIPAA Journal](https://www.hipaajournal.com/healthcare-data-leaks-on-github-credentials-corporate-data-and-the-phi-of-150000-patients-exposed/)
- **Scotiabank (2019):** source code, credentials, DB access keys public for months. [The Register](https://www.theregister.com/2019/09/18/scotiabank_code_github_leak/)
- **Toyota T-Connect (2017–2022):** hardcoded customer-data-server key public for five years; ~296,019 customers affected. [GitGuardian](https://blog.gitguardian.com/toyota-accidently-exposed-a-secret-key-publicly-on-github-for-five-years/)
- **Red Hat (2025):** breached private repos contained customer engagement reports — customer data stored in repos at all becomes breach payload. [Red-Team News](https://redteamnews.com/threat-intelligence/data-breach/red-hat-github-breach-exposes-sensitive-customer-infrastructure-data/)

### Quantification

- GitGuardian State of Secrets Sprawl 2025: 23.8M new secrets on public GitHub in 2024 (+25% YoY); 70% of 2022's leaked secrets still valid in 2025. [Report](https://www.gitguardian.com/state-of-secrets-sprawl-report-2025) · 2026 edition: ~29M, 81% surge in AI-service leaks. [Blog](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/)
- Meli et al., "How Bad Can It Git?" (NDSS 2019): 100,000+ repos with leaked secrets, thousands of new leaks daily. [Paper](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf)
- Jupyter: every executed cell output (DataFrame previews, SQL results) is serialized into the `.ipynb` JSON — a `SELECT * FROM customers` becomes a permanent PII snapshot in history. [Sentra](https://www.sentra.io/learn/jupyter-notebook-scanning-the-data-science-blind-spot-leaking-your-sensitive-data)
- Caveat: industry telemetry counts *secrets*; PII-in-data-files is under-measured, not rare.

### Prevention tooling (verified)

- **gitleaks** — custom `gitleaks.toml` rules (regex+entropy+path) can cover PII shapes; official pre-commit hook; now feature-complete/security-patches-only. https://github.com/gitleaks/gitleaks
- **TruffleHog** — 800+ detectors with live verification; scans history, orgs, S3, images; custom detectors. https://github.com/trufflesecurity/trufflehog
- **GitHub push protection** — blocks supported *credential* patterns only; a customers.csv sails through; write-access users can bypass (audited). [Docs](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)
- **pre-commit** framework — `check-added-large-files`, `detect-private-key`, hosts the scanner hooks. https://pre-commit.com/
- **nbstripout** — git clean/smudge filter stripping notebook outputs before commit. https://github.com/kynan/nbstripout
- `.gitignore` limits: doesn't untrack already-committed files; `git add -f` overrides; misses renamed exports. Seatbelt, not scanner.

### Remediation

- GitHub's official guidance now recommends **git-filter-repo ≥ 2.47 with `--sensitive-data-removal`**; rotate/revoke FIRST; rewrites don't purge cached views, `refs/pull/*` (GitHub Support only), clones, or forks. [GitHub docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) · [git-filter-repo](https://github.com/newren/git-filter-repo) · [BFG](https://rtyley.github.io/bfg-repo-cleaner/) (fine for simple cases, no longer first choice)
- For customer data, history rewrite is containment, not remediation: assume scraping within minutes; run breach-notification/DSAR processes.

### Safe test data

- **Faker**: Python [joke2k/faker](https://github.com/joke2k/faker); JS **@faker-js/faker** (the maintained fork — the original faker.js died Jan 2022). https://github.com/faker-js/faker
- **PostgreSQL Anonymizer** (Dalibo): static/dynamic masking + anonymous dumps via `SECURITY LABEL`. https://gitlab.com/dalibo/postgresql_anonymizer
- **Greenmask**: `pg_restore`-compatible anonymized/subsetted dumps, deterministic transformers. https://github.com/GreenmaskIO/greenmask
- Churn warning: **Snaplet shut down 2024-08-31**; **Neosync archived 2025-08-30** — don't recommend either.
- Anonymize **at export time**, before a raw dump ever exists outside prod.

### Adjacent surfaces

- Issues/PR text get secret scanning, but PII and screenshots get no automated protection. [GitHub public monitoring](https://github.blog/changelog/2026-07-01-secret-scanning-public-monitoring-for-enterprises/)
- Committed `logs/`, `*.bak`, `dump.rdb`, `db.sqlite3`; `.DS_Store` leaking directory listings ([Microsoft Vancouver case](https://cybernews.com/security/microsoft-vancouver-leaking-website-credentials-via-overlooked-ds-store-file/)); `.ipynb_checkpoints/` holding stale outputs.

---

## Part B — Leaks beyond git

### Logs

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): passwords never in any form; tokens/session IDs never in full; log *events*, not *payloads*.
- Pino built-in `redact` paths with wildcards. [Docs](https://github.com/pinojs/pino/blob/main/docs/redaction.md)
- **Facebook 2019:** plaintext passwords of 200–600M users in internal logs, searchable by ~20k employees ([Krebs](https://krebsonsecurity.com/2019/03/facebook-stored-hundreds-of-millions-of-user-passwords-in-plain-text/)); Irish DPC fined Meta **€91M** (2024) over it ([DPC](https://www.dataprotection.ie/en/news-media/press-releases/DPC-announces-91-million-fine-of-Meta)). **Twitter 2018:** passwords logged pre-hash; 336M resets ([TechCrunch](https://techcrunch.com/2018/05/03/twitter-password-bug/)).
- Log retention = GDPR Art. 5(1)(e) storage-limitation liability. [Art. 5](https://gdpr-info.eu/art-5-gdpr/)

### Error trackers & session replay

- Sentry: `sendDefaultPii` off by default; `beforeSend` client scrub; server-side scrubbing as backstop. [Sensitive data docs](https://docs.sentry.io/platforms/javascript/data-management/sensitive-data/) · [Scrubbing](https://docs.sentry.io/security-legal-pii/scrubbing/)
- Session replay: Sentry masks all text/blocks all media by default ([privacy docs](https://docs.sentry.io/platforms/javascript/session-replay/privacy/)); LogRocket `inputSanitizer`/`data-private` ([privacy](https://docs.logrocket.com/docs/privacy)); Fullstory "Private by Default" ([docs](https://help.fullstory.com/hc/en-us/articles/360044349073-Fullstory-Private-by-Default)). Lesson: mask-everything-then-allowlist.
- PII in URLs violates GA terms; URLs propagate to access logs, Referer, history, analytics. [Google guidance](https://support.google.com/analytics/answer/6366371?hl=en)

### LLM APIs

- Anthropic: commercial inputs/outputs not used for training by default ([policy](https://privacy.claude.com/en/articles/7996868-is-my-data-used-for-model-training)); retention documented per feature, ZDR agreements for eligible customers with a Covered-Models 30-day carve-out ([retention docs](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), [covered models](https://support.claude.com/en/articles/15425996-data-retention-practices-for-covered-models)). Policies evolving in 2026 — re-verify quarterly ([Axios](https://www.axios.com/2026/08/19/openai-previews-zero-retention-safety-system-as-anthropic-requires-data-logs)).
- OpenAI: API data not used for training by default; abuse logs up to 30 days; ZDR for approved customers. [Docs](https://developers.openai.com/api/docs/guides/your-data)
- Key insight: "not used for training" ≠ "not retained." [OWASP LLM02:2025 Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/) is #2.

### Prod data outside prod

- Dev/staging copies: PostgreSQL Anonymizer / Greenmask (above), anonymize at export.
- CI: GitHub Actions masks registered secrets + `::add-mask::`, but derived values aren't auto-masked; no real customer records in CI. [Secrets docs](https://docs.github.com/actions/security-guides/encrypted-secrets)
- Backups: prod-grade PII with weaker controls; include in retention/deletion scope.
- `.env` sharing via chat → secret managers with CLI injection (Infisical open-source/self-hostable, Doppler managed). [Comparison](https://infisical.com/infisical-vs-doppler)

### Data-minimization architecture

- GDPR Art. 5(1)(c)/(e) as engineering rules: don't add the column; retention is a scheduled job that actually deletes, verified by a test.
- Envelope encryption: per-record data keys, AES-256-GCM, KMS-wrapped; **crypto-shredding** (destroy the key) makes deletion reach backups. [AWS KMS details](https://docs.aws.amazon.com/pdfs/kms/latest/cryptographic-details/kms-crypto-details.pdf)
- Art. 17 erasure fans out to every subprocessor (error tracker, replay, analytics, email, LLM, log store, backups); the subprocessor inventory *is* the leak map. [Art. 17](https://gdpr-info.eu/art-17-gdpr/)
- Browser: no PII/tokens in localStorage ([OWASP HTML5 CS](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)); bundles + source maps ship to every visitor.
