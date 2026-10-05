# Server and worker deployment

This release requires a coordinated upgrade. The `ICEvirtue` executable only serves HTTP. Start one or more `ICEvirtue-worker` processes to execute scans and schedules. Existing HTTP routes remain available. Run history is available from Profiles → Run history; worker heartbeats and queue age appear in the Admin dashboard.

## Components and ownership

- `internal/app`: command-line configuration, dependency construction, ordered cleanup.
- `internal/api`: authentication middleware, request validation, HTML/JSON/SSE delivery and dashboard read services.
- `internal/accounts`, `appconfig`, `profiles`, `wordlists`: account, configuration, profile and upload services.
- `internal/database`: server-owned schema/data migrations and SQLite connections.
- `internal/jobs`: queue admission, claims, fences, heartbeat, recovery, retention and leadership storage.
- `internal/scheduler`: replacement cron schedules and leader election; every scheduled admission is fenced in SQLite.
- `internal/engine`: coordinator, stages, adapters, injected process executor and finding store. Tool execution never runs inside a database transaction.
- `internal/events`, `notifications`: transactionally written outbox and notification delivery.
- `web/static/js/dashboard`: API, URL state, views, notifications, SSE and history modules. Templates contain no executable inline scripts or handlers. Scripts require the same origin under CSP.

Both processes need the **same absolute database and upload paths**, service identity and local filesystem. SQLite WAL permits concurrent readers and one writer; write transactions acquire ownership immediately, use bounded finding batches, and have a five-second busy timeout. Do not use NFS/SMB or run workers on different hosts. Only the server migrates and reconciles uploads. Workers and the administration CLI refuse an absent or incompatible schema.

## Build and first start

```sh
make build
# In terminal/service 1: creates the schema and private upload directory.
bin/ICEvirtue --db-path /absolute/state/icevirtue.db --upload-dir /absolute/state/uploads --web-dir /absolute/ICEvirtue/web
# After the server has initialized the schema:
bin/ICEvirtue-admin create --db-path /absolute/state/icevirtue.db --username admin --password 'use-a-strong-password'
# In separate terminals/services; repeat to add workers:
bin/ICEvirtue-worker --db-path /absolute/state/icevirtue.db --upload-dir /absolute/state/uploads --tool-home /absolute/worker-one
```

The server keeps HTTP/listener, cookie, JWT, origin, template and upload flags. `--tool-home`, `--tool-paths` and `--waymore-config` belong exclusively to the worker. Configure tool timeouts, global concurrency and scan options through Application configurations. Each claimed job snapshots the current configuration revision and pins its selected wordlists. Concurrency defaults to two scans **across all workers**. Admission permits 100 waiting jobs and one active or waiting job per profile.

## Leases, recovery and history

Workers poll once per second, renew 60-second scan leases every 10 seconds, heartbeat every 10 seconds and reap expired leases every 15 seconds. Every finding batch, diagnostic write and completion checks the claim token and expiry. A renewal error cancels the process group. A stale worker cannot commit findings or finish another worker's job.

A stopped or crashed scan becomes `interrupted`; committed findings remain. Recovery releases pins and removes the active job. **Interrupted scans are never retried automatically.** Queue another scan manually when appropriate. Other outcomes are `completed`, `completed_with_errors`, `halted` (an input stage returned no usable results), or `failed` (storage/setup/internal failure). A queued job with unavailable selected wordlists fails and does not block later jobs.

History records the source, revision, timestamps, new-finding count, stage input/output counts, and controlled summaries. Tool rows have `scope=execution` for actual process lifetime and `scope=result` for decoded adapter results and skipped tools. Execution rows survive a process crash. Diagnostic rows never contain raw output or discovered credential values. Findings retain their existing evidence fields and retention behavior.

Finished history is pruned after 30 days; active history is retained. Heartbeats remain visible for 24 hours and are marked offline after 30 seconds. Maintenance runs at worker startup and hourly. The outbox retains at most 100,000 events and a 24-hour replay window; SSE delivers IDs and replays `Last-Event-ID`. A missing replay window produces `stream_reset`, which refreshes dashboard collections. Reconnects use native EventSource backoff.

The scheduler lease lasts 30 seconds and is renewed every five seconds. Each leadership epoch receives a new token. Invalid schedule reloads preserve the last working schedule and are retried. A new leader only installs future occurrences; missed schedule times are skipped. Queue claiming does not depend on scheduler availability or HTTP uptime.

## Service installation

Create a dedicated `icevirtue` account. Install the binaries from `bin/` under `/usr/local/bin`, the `web` directory under `/opt/icevirtue/web`, and the supplied units from `deploy/` under `/etc/systemd/system`. Configure tool binaries on the worker PATH or add worker `--tool-paths` overrides. Each worker has a separate writable tool home/cache. Set `--secure-cookies` on the server when serving through HTTPS.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now icevirtue.service
# Wait for successful server initialization, then provision the administrator.
sudo systemctl enable --now icevirtue-worker@1.service icevirtue-worker@2.service
```

The worker units intentionally do not require the web unit. Inspect worker tool logs with `journalctl -u 'icevirtue-worker@*'`; the dashboard's Server logs show the web process only. `KillMode=control-group` terminates tool descendants on service failure. SIGTERM stops scheduling, cancels tools, finalizes interrupted runs where ownership remains valid, and closes storage last. The server closes streaming request contexts before draining HTTP.

## Coordinated upgrade, backup and rollback

1. Stop the old server and all workers. Verify their processes and tools have stopped.
2. Back up the SQLite database **and private upload directory as one pair**, plus the signing key and service configuration. With all writers stopped, checkpoint SQLite using `sqlite3 /path/icevirtue.db 'PRAGMA wal_checkpoint(TRUNCATE);'`, then copy the database and uploads to the same dated backup directory. If checkpointing is unavailable, preserve the database and existing `-wal`/`-shm` sidecars together while every process remains stopped.
3. Install the new binaries and static files together. Start only the server. It migrates the schema, removes stored scan flags, clears legacy running jobs and reconciles uploads. Legacy queued work remains queued.
4. Confirm successful initialization and sign-in, then start workers. Confirm fresh heartbeats, a working schedule, and a disposable manual scan.

For rollback, stop every new process and restore the **paired pre-upgrade database and uploads**, signing key and old binaries/static files. Remove the new database's sidecars before restoring the old set. Do not run the old binary against the migrated database. A rollback loses changes made since the backup.

For routine consistent backups, briefly stop both server and workers and follow the same paired procedure. A database-only backup can refer to wordlists absent from its upload snapshot.

## Scratch limits

Captured stdout is capped at 1 GiB per tool. Scan scratch monitors the filesystem's free-space floor (64 MiB); there is no aggregate per-scan scratch-byte cap. Tool-created archives and output files can be large. Provision worker caches accordingly. A scratch failure cancels the scan and preserves already committed findings. After a SIGKILL or host crash, inspect and remove abandoned `icevirtue-scan-*` directories only while their worker is stopped; normal shutdown removes scratch automatically.

## Verification

`make test` exercises route/role boundaries, migrations, parsers, lease fencing, concurrent OS worker processes, leader replacement, storage rollback and worker kill/shutdown with fake tools. Tests require local sockets. Browser tests use disposable fixture data; `ICEVIRTUE_SMOKE_URL` selects the fixture server and `ICEVIRTUE_CONFIG_TESTS=1` enables configuration mutations. Never point the suite at production.
