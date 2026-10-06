> This release separates the server and scan workers. Follow [the coordinated upgrade and rollback procedure](modularity.md) before using these configuration instructions.

# Application configuration

Open **Settings → Admin dashboard → Application configurations**. The three forms use administrator-only APIs. Each form saves its whole section with the loaded configuration revision; stale edits return 409 and remain visible until the administrator reloads saved settings.

## Defaults and limits

Password policy defaults to 8–26 Unicode code points with an independent 72-byte UTF-8 cap. Allowed policy values satisfy `8 ≤ minimum ≤ maximum ≤ 72`. Passwords are not trimmed, normalized, or truncated. New/reset passwords in both the web UI and administration CLI use the stored policy; existing passwords still authenticate.

Nuclei, Amass, WAF detection and secret hunting start enabled. DNSX and directory discovery start disabled, with no wordlists selected. Amass and DNSX remain Full Mode operations. Secret-hunting skips also disable its collection tools. Verbose logging and wide targets default off. Existing findings survive skipped stages.

WAF timeout defaults to 30 seconds (1–300). Waymore defaults to 5,000 responses (1–50,000). Scan concurrency defaults to two (1–4), with at most 100 waiting jobs across manual and scheduled requests. Duplicate requests return 409; queue saturation returns 429. Queued scans use settings at actual start; active scans retain their snapshot. Worker recovery preserves queued jobs and interrupts only expired active leases, without rerunning them. A web restart does not stop workers. Graceful worker shutdown cancels tool process groups and releases its owned jobs. A server lock serializes server migration/upload reconciliation; multiple workers and the CLI remain usable.

Wordlists are uncompressed UTF-8 `.txt`, `.lst` or `.wordlist` files, at most 1 GiB each, 10 GiB total, and 50 stored files. Upload admission is one at a time, with a one-hour total deadline and a one-minute inactivity deadline. Lines are limited to 4 KiB, and NUL bytes, empty effective files, additional multipart fields/files and malformed UTF-8 are rejected. A full 1 GiB reservation and at least 1 GiB of free filesystem space are required at admission, even for a small upload. Failed cleanup retains quota until recovery can safely remove the file.

Files preserve their exact uploaded bytes. Filenames are `<sha256-of-content>_directory-wordlist` or `<sha256-of-content>_subdomain-wordlist`; original names are display metadata. Duplicate content of the same type returns 409. Files cannot be deleted while selected (even for a disabled stage) or pinned by an active scan. Uploading does not select or enable a list automatically.

Directory discovery validates candidate responses against random nonexistent paths and retains ambiguous responses as Unknown. See [directory discovery validation](directory-discovery.md) for filters, redirect scope, and limits. Directory discovery deduplicates words in a private SQLite scratch database, uses 50 workers per scan, and persists findings in batches of 100. The stage has a two-hour deadline and a 4 GiB scratch database limit; it retains already committed findings if interrupted. DNSX parsing and the combined discovery set are capped at 100,000 unique subdomains and report incomplete discovery when capped. Each scan owns a private scratch directory. A one-second monitor cancels tools when filesystem free space falls below 64 MiB. There is no combined per-scan scratch cap. Go-owned stdout has a 1 GiB cap per tool. External tool writes can overshoot between monitor ticks; use a filesystem quota when a strict disk boundary is required. These are safeguards, not a guarantee that a 1 GiB list finishes scanning within the execution budget.

## Deployment and upgrade

Remove the old behavior flags from service `ExecStart` and scripts: `--verbose`, `--dnsx-list`, `--directory-list`, `--skip-amass`, `--skip-nuclei`, `--wide-targets`, `--waymore-response-limit`, `--waf-process-timeout`. They are no longer accepted or silently ignored. On first startup the database receives the defaults above; earlier command-line values cannot be inferred from SQLite and must be entered in the dashboard.

The server keeps `--db-path`, `--web-dir`, `--api-port`, `--jwt-secret`, `--secure-cookies`, `--session-ttl`, `--trusted-origin`, and `--reload-templates`. Move `--tool-home`, `--tool-paths` and `--waymore-config` to worker commands. The new `--upload-dir` defaults to `uploads` under the service's working directory. Keep that directory outside the web tree, writable only by the service account. Directory/file modes are 0700/0600 on a filesystem that enforces Unix permissions. Upload APIs never accept server paths or executable configuration.

Back up SQLite and the upload directory together. Keep the same upload directory across restarts; startup fails if a ready file is missing or unsafe. Staged uploads and interrupted deletions are reconciled before workers start. Do not share one upload directory between unrelated ICEvirtue databases.

A reverse proxy must allow a body slightly larger than 1 GiB (multipart overhead), streaming request bodies and the upload timeout. The application enforces its own limits. A normal small JSON-body limit on the proxy's upload route will reject large files before they reach ICEvirtue.

## API contract

All routes below require a live administrator session. Mutations additionally require accepted same-origin metadata and `X-CSRF-Token` obtained from the authenticated settings page. Sessions and permissions are checked again inside committing transactions. Configuration JSON bodies are limited to 64 KiB; unknown, duplicate, missing and null fields are rejected.

`GET /api/admin/configuration` returns `{ "configuration": { "revision": 1, "password_policy": {...}, "scan": {...}, "tools": {...}, "updated_by": "...", "updated_at": "..." }, "limits": {...} }`.

`PUT /api/admin/configuration/password-policy`, `/scan` and `/tools` accept `{ "revision": 1, "settings": {...} }` and return the complete updated configuration. Password settings require `minimum` and `maximum`. Scan settings require all of `skip_nuclei`, `skip_amass`, `skip_dnsx`, `skip_waf`, `skip_directory`, `skip_secrets`, `verbose`, `wide_targets`, `dnsx_wordlists`, and `directory_wordlists`. Wordlist selections are arrays of ready IDs with the matching type; enabling a wordlist stage requires a nonempty selection. Tools settings require `waf_timeout_seconds`, `waymore_response_limit`, and `max_concurrent_scans`.

`GET /api/admin/wordlists` returns ready metadata with IDs, display names, type, byte/entry counts and SHA-256; no physical paths. `POST /api/admin/wordlists?kind=subdomain` (or `directory`) accepts a multipart request with exactly one `file` part. `DELETE /api/admin/wordlists/{id}` returns 204 or 409 if still referenced. Upload admission returns 429 when busy, 413 for quota exhaustion, and 400 for invalid content. Errors do not expose server paths. Uploads and mutations emit structured audit events to the process log.

`PUT /api/profiles/{id}/schedule` also accepts optional `enabled` alongside `schedule`. Disabling a schedule removes that profile's pending scheduled job atomically, preserving any queued manual request. Profile responses expose `IsQueued`, and overview responses expose `is_queued`.

## Verification

Run `go test ./...` and `go vet ./...`. Focused concurrency checks use `go test -race ./internal/api ./internal/accounts ./internal/appconfig ./internal/engine ./internal/wordlists ./internal/scheduler`. Streaming upload coverage generates a 16 MiB fixture without materializing it in memory; it does not require allocating a full 1 GiB file.

The optional browser test changes global settings, so use a disposable database and run one browser project at a time: `ICEVIRTUE_CONFIG_TESTS=1 npm run test:ui -- web/tests/application-configuration.spec.mjs --project=chromium --workers=1`. Set `ICEVIRTUE_SMOKE_URL`, `ICEVIRTUE_TEST_USER`, and `ICEVIRTUE_TEST_PASSWORD` for the isolated server, or use the existing mock-data defaults.
