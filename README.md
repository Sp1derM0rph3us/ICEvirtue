# ICEvirtue

![](https://github.com/Sp1derM0rph3us/ICEvirtue/blob/dev/ICEvirtue_login.png)

ICEvirtue is the netrunner's most essential tool. It executes a standardized reconnaissance and enumeration workflow and stores the results inside **target profiles**, allowing netrunners to focus on what really matters: actually hacking.

You register a domain once, tell ICEvirtue how often to look at it, and it _keeps_ looking. Every run is diffed against everything it has seen before for that profile, so the dashboard tells you what is _new_ rather than dumping the same ten thousand subdomains on you every night. Findings are grouped per profile into subdomains, alive hosts, directories, vulnerabilities and secrets, and the dashboard updates itself live over Server-Sent Events while a scan is running.

Two binaries make up the project. `ICEvirtue` is the engine and the web dashboard, and `ICEvirtue-admin` is the small companion tool you use to create the **first login credentials**, because there is no default account. Every other account after the first boot can be created through the web dashboard.

## How The Pipeline Works

The application follows a continuous reconnaissance workflow separated into five stages, each feeding the next.

**Stage 01, Basic Recon.** ICEvirtue runs [Subfinder](https://github.com/projectdiscovery/subfinder) for passive subdomain discovery. In Full Mode it also passes `-all` to Subfinder and runs [Amass](https://github.com/owasp-amass/amass), unless Amass is disabled in Application configurations. If DNSX is enabled with selected uploaded wordlists, it additionally runs [DNSX](https://github.com/projectdiscovery/dnsx) once per wordlist for active DNS bruteforcing. Results from all three sources are merged and de-duplicated before anything else happens.

**Stage 02, Web Validation.** Every discovered name is probed with [HTTPX](https://github.com/projectdiscovery/httpx) to collect status code, page title, web server, resolved IPs and Web Application Firewall brand. Every HTTP-responsive endpoint then undergoes active [WAFW00F](https://github.com/EnableSecurity/wafw00f) detection, regardless of status code. Each WAFW00F process has a 30-second wall-clock limit by default; timed-out endpoints do not delay the next worker job. The first prioritized product match is saved; a generic-only match is shown as **Unknown WAF**, and a successful probe with no match as **No WAF detected**. Failed WAF probes preserve the last successful observation. WAFW00F probes do not follow redirects, to avoid scanning a different host. All subdomains are saved to the profile whether they are alive or not, but only hosts answering `200`, `301`, `302` or `307` are carried forward to later stages.

**Stage 03, Directory and File Fuzzing.** If directory discovery is enabled with selected uploaded wordlists, a built-in concurrent fuzzer walks the carried-forward hosts. You can pass several wordlists and the engine merges and de-duplicates them, so overlapping lists cost you nothing. Requests do not follow redirects, and a path is recorded when it answers `200`, `301`, `302`, `403` or `405`. Directory discovery starts disabled until wordlists are uploaded and selected.

**Stage 04, Vulnerability Scanning.** Unless Nuclei is disabled in Application configurations, [Nuclei](https://github.com/projectdiscovery/nuclei) is run against the carried-forward hosts to identify vulnerabilities and misconfigurations. Template ID, matched URL, severity, name and description are stored per finding.

**Stage 05, Secret Hunting.** ICEvirtue uses [Waymore](https://github.com/xnl-h4ck3r/waymore) to discover historical JS/data URLs and download archived responses. It validates historical URLs that are still live with HTTPX, crawls live hosts with [Katana](https://github.com/projectdiscovery/katana), and extracts script references with [Subjs](https://github.com/lc/subjs). [SecretHound](https://github.com/rafabd1/SecretHound) scans live URLs and archived files in one run; [Mantra](https://github.com/brosck/mantra) scans live URLs only. The stage is best effort: partial tool output remains usable.

## Using The Dashboard

Start in **Profiles** to add a target domain, for instance `hackerone.com`, and choose how often ICEvirtue should scan it: every day, week, month or year, at a time of day you pick. This page lists each profile's schedule, scan status and last run, and lets you run a scan, edit its schedule or delete it. Every profile created through the dashboard runs in Full Mode, so the breadth of the pipeline is controlled by the engine flags rather than per profile.

![](https://github.com/Sp1derM0rph3us/ICEvirtue/blob/dev/ICEvirtue_dashboard_2.png)

**Home** gives the selected profile an overview: total identified assets, the share that have ever answered HTTP, the last scan and last identified asset change in UTC, severity counts, the highest-priority Nuclei findings, and a de-duplicated list of detected WAF technologies.

![](https://github.com/Sp1derM0rph3us/ICEvirtue/blob/dev/ICEvirtue_dashboard_1.png)

Scheduling follows the **system clock of the machine ICEvirtue runs on**, and there is currently no way to set a different timezone in the application. If you are hosting on a VPS, check what the server's clock is set to, otherwise your scans will fire at a different local time than you intended.

Under the hood, the schedules the dashboard produces are human-readable strings such as `every day at 14:30`. The API also accepts `@every 12h` style intervals and raw cron expressions, and because the scheduler is second-granular a raw cron expression needs six fields (`seconds minutes hours day-of-month month day-of-week`) rather than the usual five.

**Findings** holds the assets identified for each profile. Choose a profile and use the **Nodes** tab to see each asset's HTTP status, counts of observations, first-seen time and last sync. You can sort, filter and page through the nodes. Click a node to inspect its IP address, WAF detection, and its Findings, Directories and Credentials tabs, or use the icon at the far right of its row to open the asset in your browser. A node marked **No response** has no recorded HTTP response; this is not a live availability check. Findings appear as the scan stages complete.

![](https://github.com/Sp1derM0rph3us/ICEvirtue/blob/dev/ICEvirtue_dashboard_3.png)

The **Credentials** tab in Findings shows every credential identified for the selected profile, regardless of which node it came from, with its type, value, source and scanning engine. Live findings link to their source files. Findings from downloaded historical files retain the original URL for node attribution and link to the Wayback replay or an archive record. A finding observed in both places shows both links. Historical Mantra findings without a source remain **Unattributed**. Mantra results use the type **generic** because Mantra does not identify a provider. Older credentials without recorded scanner provenance show **Unknown** as the engine. A node's own Credentials tab shows findings attributed to that node, including risk, occurrence count, and expandable description and context when available.

![](https://github.com/Sp1derM0rph3us/ICEvirtue/blob/dev/ICEvirtue_dashboard_4.png)

### When A Run Stops Early

Decisions about stopping are made per stage, never per tool. A stage attempts every tool available to it, merges whatever came back, saves that to the profile, and only then asks whether the run still has enough to continue. No single tool can end a run: if Subfinder cannot execute, Amass and `dnsx` still get their turn, and whatever they find carries the run forward.

The rule for whether a stage can stop the run at all is simply whether a later stage consumes its output. Discovery and validation produce the input everything else depends on, so those two can stop a run. Fuzzing, vulnerability scanning and secret hunting are leaves, since nothing reads their findings, so they can only run or be skipped. A leaf stage failing outright never ends the run.

That leaves exactly two conditions that stop a run, and both mean there is genuinely nothing left to work with:

Discovery produced no subdomains at all, meaning every source either failed or came back empty. Note that this is checked against the **merged** set, so Subfinder finding names keeps the run going even when Amass and `dnsx` each contribute nothing. If you see this halt, the most likely explanation is a typo in the target domain.

Validation found no host that answered HTTP. Every later stage needs a live host, and stage 05 validates its archived URLs against live hosts too, so there is nothing productive left to attempt.

Anything else is reported and moved past. A tool that is missing, errors out, or exceeds its time budget is recorded as a failure for that stage, and a stage with no work to do is recorded as skipped with the reason. Skipping is not failing: disabling DNSX or Nuclei in Application configurations shows up as `skipped`, not as a problem.

Because these tools stream their results, a tool that dies partway through still contributes everything it emitted first. Those runs are marked `PARTIAL` in the stage summary, so a Nuclei scan killed at the end of its two hour budget keeps the findings it had already reported rather than throwing the whole scan away. The same applies when a run halts: everything collected before the halt is saved to the profile and appears in the dashboard, so a run that stops at validation still leaves you its subdomains.

Each stage logs a summary showing exactly which tools contributed what:

```
[+] [Target: example.com] Stage 01 Discovery: 4044 unique result(s) from 2 of 3 tool(s)
      subfinder      ok         3987
      amass          FAILED        0  amass not found: install it and make sure it is on PATH (searched: ...)
      dnsx[wl1.txt]  ok           57
      dnsx[wl2.txt]  skipped         DNSX is disabled or no wordlist selected
```

## Requirements

You need Go 1.26 or newer to build, and **all of the external tools listed above have to be installed and reachable on the `PATH` of the user ICEvirtue runs as**. This is the single most common reason a fresh install does not work, so ICEvirtue-worker prints a preflight summary at startup telling you exactly which tools it found and which it could not, before any scan is ever triggered. Check that line first when a stage fails.

Not every tool is needed in every configuration. Which ones ICEvirtue actually requires depends on the flags you start it with:

| Tool | Stage | Needed when |
|---|---|---|
| `subfinder` | 01 | always |
| `amass` | 01 | unless disabled in settings |
| `dnsx` | 01 | when enabled with selected uploaded wordlists |
| `httpx` | 02, 05 | always |
| `wafw00f` | 02 | attempted for every HTTPX-responsive endpoint; active probes are sent |
| `nuclei` | 04 | unless disabled in settings |
| `waymore`, `katana`, `subjs`, `mantra`, `secrethound` | 05 | attempted when inputs permit, failures are non-fatal |


**OBS**: Stage 03 needs no external tool at all, since the fuzzer is built in.

Build SecretHound with `go build -o secrethound ./cmd/secrethound` from its repository and put the binary on `PATH`, or pin it with `--tool-paths secrethound=/absolute/path/to/secrethound`. ICEvirtue supplies a `.urls` list and reads SecretHound's JSON output. SecretHound's default TLS behavior is used.

The Credentials list shows which engine found each result. A node's Credentials tab also shows SecretHound's risk, occurrence count, description, and context. New Mantra results retain the reported source URL and appear under that node; historical unattributed Mantra results remain in the general list. Existing findings show **Unknown** as their engine until a scanner rediscovers them.

### When A Tool Name Belongs To Something Else

On Debian and its derivatives, including Kali and Parrot, the name `httpx` is already taken. The `python3-httpx` package owns `/usr/bin/httpx`, which is the CLI of an unrelated Python HTTP client, so those distributions ship projectdiscovery's httpx as **`httpx-toolkit`** instead. Looking a tool up by name therefore finds the wrong program, and it fails on the first flag it is given:

```
stderr: Usage: httpx [OPTIONS] URL
        Error: No such option: -s
```

ICEvirtue handles this without needing to know which distribution it is on. For every tool built on projectdiscovery's flag library (`subfinder`, `httpx`, `dnsx`, `nuclei`, `katana`) it tries the plain name first and then the known packaging alternatives, and it accepts a candidate only if that binary answers `-version` with exit status zero and a version number. A program that merely shares the name almost never does both, so the imposter is rejected and the search continues. The startup preflight prints the binary it settled on for each tool:

```
[+] Preflight: 2/8 required tools resolved
      subfinder (/usr/bin/subfinder)
      httpx (/usr/bin/httpx-toolkit)
```

If nothing passes the probe, ICEvirtue uses the first candidate it found rather than refusing to run, on the grounds that the probe might be wrong about a working binary, but it says so clearly and tells you how to override it. When that happens, or whenever you want to be explicit, pin the binary yourself:

```Shell
ICEvirtue-worker --tool-paths httpx=/usr/bin/httpx-toolkit,nuclei=/opt/tools/nuclei
```

An explicit `--tool-paths` entry is used as given, with no discovery and no probing.

Do not solve this by removing `python3-httpx`. On a typical Kali or Parrot install `python3-dnspython` depends on it, and removing it takes dnspython with it. If you would rather fix it at the system level than pass a flag, symlink the real binary somewhere that precedes `/usr/bin` on your `PATH`:

```Shell
sudo apt install httpx-toolkit
sudo ln -s /usr/bin/httpx-toolkit /usr/local/bin/httpx
```

One more thing worth knowing: `katana`, `subjs` and `mantra` commonly come from `go install` and land in `$GOPATH/bin`, usually `~/go/bin`. Waymore is a Python tool installed separately. Ensure all binaries are on the systemd service's `PATH`, or pin them with `--tool-paths`. Use `--waymore-config /path/to/config.yml` for Waymore API keys; without it ICEvirtue uses a temporary config that does not exclude common JS paths. Tools Settings sets Waymore's maximum response count (default 5000); it is not a byte-size limit.

## Installation

Build both binaries and drop them somewhere on the system `PATH`:

```Shell
sudo su
# type in sudo password...

git clone https://github.com/Sp1derM0rph3us/ICEvirtue.git
cd ICEvirtue
go build -o /usr/bin/ICEvirtue .                 # web server
go build -o /usr/bin/ICEvirtue-worker ./cmd/worker # scans and scheduling
go build -o /usr/bin/ICEvirtue-admin cmd/admin/main.go   # user management
chmod 775 /usr/bin/ICEvirtue*
```

If you installed any of the recon tools with `go install`, they landed in `$GOPATH/bin` (usually `~/go/bin`). That directory is on your interactive `PATH` but almost certainly not on the `PATH` of a service, so either copy those binaries into `/usr/bin` too or set the service `PATH` explicitly as shown further down.

**Deployment change:** scans and scheduling now require separate worker processes. Read [server/worker deployment and upgrade instructions](docs/modularity.md) before upgrading.

## Setting Up

ICEvirtue requires the `web` folder, a server-initialized database, a dashboard user, and at least one scan worker. Start the web server once before running the administration CLI.

The `web` folder holds the dashboard, split into two directories that are treated very differently:

```
web/
├── templates/      the HTML pages. Never served directly.
│   ├── login.html
│   └── home.html
└── static/         only css/ and js/ are served publicly.
    └── css/
        ├── output.css
        └── theme.css
```

Only `web/static` is exposed over HTTP, and only its `css` subdirectory is reachable. That separation is the point: an earlier layout served the whole `web` folder, so `GET /static/template.html` handed the entire authenticated dashboard to anyone and `GET /static/` returned a directory listing. **Anything you put under `web/static` is public. Anything under `web/templates` is not.**

ICEvirtue looks for `web` relative to its working directory. Running from a checkout already works; anywhere else, copy the folder next to wherever the application will live, or point `--web-dir` at it:

```Shell
mkdir -p /opt/icevirtue
cp -r ./ICEvirtue/web /opt/icevirtue

# or leave it where it is and say so
ICEvirtue --web-dir /srv/icevirtue/web
```

**Upgrading from a build before this layout:** the old flat `web/` (with `login.html`, `template.html` and `css/` at the top level) will not be found. Replace the deployed folder with the new one rather than merging them — the engine looks for `web/templates/home.html` and `web/static/css/output.css` at exactly those paths.

There is no default account, so create one with `ICEvirtue-admin`. The same command also creates and migrates the database file if it does not exist yet:

```Shell
ICEvirtue-admin create --username 'netrunner' --password 'super-secret-password' --db-path /opt/icevirtue/icevirtue.db
```

**Point the engine at that same database.** `ICEvirtue` defaults to `icevirtue.db` relative to its working directory, so if the two disagree the dashboard silently opens a brand new empty database and then refuses your login, because the user you just created is not in it. Pass `--db-path` on both sides whenever they are not in the same directory:

```Shell
ICEvirtue --db-path /opt/icevirtue/icevirtue.db
```

Because the password is passed as a command line argument it will land in your shell history and is briefly visible in the process list. On a shared box, prefer creating the user from a root shell with history disabled.

## Running ICEvirtue

Start the server first to migrate the database, then start workers using the same database and upload paths:

```Shell
ICEvirtue --db-path /opt/icevirtue/icevirtue.db --upload-dir /opt/icevirtue/uploads
# Separate terminal/service:
ICEvirtue-worker --db-path /opt/icevirtue/icevirtue.db --upload-dir /opt/icevirtue/uploads
```

Open the dashboard on port `8888` (or choose another with `--api-port`) and navigate to **Settings → Admin dashboard → Application configurations**. Configure password policy, global scan skips, wordlists and tool limits there. DNSX and directory discovery start disabled with empty wordlist selections. Upload lists, select them, enable the desired stages, and save.

Settings persist in SQLite. Running scans keep their original configuration; queued scans take a snapshot when they start. Manual and scheduled scans share a queue of up to 100 waiting jobs, with two concurrent scans globally across all workers by default. [Configuration API, limits and upgrade instructions](docs/application-configuration.md).

### Server and worker flag reference

Scan behavior flags have moved to the admin configuration API and dashboard.

| Flag | Default | What it does |
|---|---|---|
| `--api-port` | `8888` | TCP port the web dashboard listens on. |
| `--db-path` | `icevirtue.db` | Path to the SQLite database. Must match the path used by `ICEvirtue-admin`. |
| `--jwt-secret` | *(auto)* | Path to the key that signs dashboard session cookies. See "Where State Lives" for how the default is chosen. |
| `--secure-cookies` | `false` | Mark the session cookie `Secure`. Turn this on whenever the dashboard is reached over HTTPS, including behind a TLS-terminating proxy. It defaults off because a browser accepts a `Secure` cookie over plain HTTP and then never sends it back, so turning it on without TLS makes login silently impossible. |
| `--session-ttl` | `24h` | How long a dashboard session lasts before it has to be re-established. |
| `--trusted-origin` | *(empty)* | An `Origin` to accept on state-changing requests in addition to the request's own host. Repeatable. **Required behind a reverse proxy that rewrites `Host`**, otherwise every write is refused with 403. See "Behind A Reverse Proxy". |
| Worker only: `--tool-home` | *(auto)* | Directory the spawned recon tools use for their own config, defaulting to `/opt/icevirtue` and falling back to `$HOME`. See "Where State Lives". |
| Worker only: `--tool-paths` | *(empty)* | Comma-separated `name=path` overrides pinning a tool to an exact binary, for example `httpx=/usr/bin/httpx-toolkit`. Skips discovery and the identity probe for that tool. |
| `--upload-dir` | `uploads` | Private wordlist storage under the service working directory; keep outside the web directory. |
| `--waymore-config` | *(empty)* | Server-managed Waymore provider configuration file. |
| `--reload-templates` | `false` | Development-only template reloading. |
| `--web-dir` | `web` | Directory holding the dashboard's `templates/` and `static/` folders. |

By default only hosts answering `200`, `301`, `302` or `307` are handed to fuzzing, Nuclei and secret hunting. The wide-target option in Scan configuration replaces that with everything HTTPX reported except a plain `404`, which brings `401`, `403`, `405`, `500` and `503` hosts into scope. A `403` on `/` tells you nothing about what `/admin` returns, and finding exactly that is the point of directory fuzzing, so the wide filter is usually what you want on a target you are allowed to be thorough with. It costs scan time proportional to how many extra hosts it lets through, and the stage log tells you how many that was:

```
[*] [Target: example.com] Target filter wide (any status except 404) selected 47 of 52 alive host(s)
```

Upload wordlists through Application configurations. Administrators select opaque file IDs; server paths are never accepted by the API.

The worker additionally accepts `--waymore-config /path/config.yml` for provider settings. See [all process responsibilities](docs/modularity.md).

## ICEvirtue-admin Reference

`ICEvirtue-admin` exists only to seed dashboard accounts. It takes a single subcommand, `create`:

```Shell
ICEvirtue-admin create --username 'netrunner' --password 'super-secret-password' [--db-path /opt/icevirtue/icevirtue.db]
```

| Flag | Default | What it does |
|---|---|---|
| `--username` | *(required)* | Username for the new dashboard account. |
| `--password` | *(required)* | Password matching the stored policy (default 8–26 Unicode characters, always at most 72 UTF-8 bytes). Stored as a bcrypt hash, never in plain text. |
| `--db-path` | `./icevirtue.db` | Database to write the account into. Must already be initialized by the web server. |

Both `--username` and `--password` are mandatory, and usernames are unique, so creating an account that already exists fails rather than overwriting it. The CLI creates an Admin account for initial provisioning and recovery. Use Settings → Admin dashboard → Users to create Viewer or Operator accounts and manage existing accounts.

## Running As A systemd Service

Install the separate [web server unit](deploy/icevirtue.service) and [worker template](deploy/icevirtue-worker@.service). Start the server to migrate and reconcile, then start `icevirtue-worker@1` and additional instances as needed. All use the same service identity and local database/uploads. Workers remain active during a web outage. See [deployment, paired backups, recovery and rollback](docs/modularity.md).

## Behind A Reverse Proxy

State-changing requests validate the browser’s `Origin` or `Referer` against the request host or the configured trusted origins. JSON API requests also require the JSON content type when they carry a body. Account and administration forms additionally require a CSRF token tied to the authenticated session.

The comparison is on the **host**, not the full origin, so terminating TLS in front of the binary is fine on its own — the browser sends `https://` while the process only ever sees `http`, and requiring a scheme match would refuse every write in the most common deployment.

What is not fine is a proxy that rewrites `Host`. If the browser sends `Origin: https://recon.example.com` while your proxy passes `Host: 127.0.0.1:8888`, the two no longer match and **every create, delete and reschedule is refused with 403** while reads keep working — a failure that looks like a broken dashboard rather than a configuration problem. Two ways out, and you want one of them:

```Shell
# Tell ICEvirtue which external origin to trust
ICEvirtue --trusted-origin https://recon.example.com

# or have the proxy preserve the original Host (nginx)
proxy_set_header Host $host;
```

The rejection is logged with both values, so the fix is readable from the log:

```
[-] Rejected a POST to /api/profiles: Origin "https://recon.example.com" does not
    match the host "127.0.0.1:8888". If this dashboard is behind a reverse proxy,
    pass --trusted-origin.
```

Two other things to set when a proxy is in front:

**`--secure-cookies`**, once the dashboard is only reachable over HTTPS. Without it the session cookie can be read by anything on the network path. With it and *without* TLS, login silently stops working — the browser accepts the cookie and then never sends it back — which is why it is not the default.

**Login rate limiting is keyed on the connecting address**, deliberately ignoring `X-Forwarded-For`: a caller who can choose the key both bypasses the limiter and can lock the real operator out. Behind a proxy on loopback that means every request looks like `127.0.0.1`, so a determined attacker can lock you out of your own dashboard for fifteen minutes. If that matters, rate-limit at the proxy instead.

## Where State Lives

ICEvirtue keeps three separate pieces of state, and each can be relocated.

The **database** is a single SQLite file holding users, roles, revocable sessions, notifications, profiles and every finding. It is controlled by `--db-path` and defaults to `icevirtue.db` in the working directory. WAL mode is enabled, so expect `icevirtue.db-wal` and `icevirtue.db-shm` alongside it. Back up all three together, or checkpoint first.

The **session signing key** is 64 random bytes generated on first run and reused afterwards, so it has to persist somewhere stable. Restarting with a different key logs everyone out. Because the location has to work both for a service and for a casual terminal run, ICEvirtue picks it in this order:

1. `--jwt-secret /path/to/key`, when you pass it.
2. An existing `./jwt.secret` in the working directory, so upgrading from an older build keeps your current key instead of invalidating every session.
3. `$STATE_DIRECTORY`, which systemd sets from `StateDirectory=icevirtue`. This is the recommended setup, since systemd creates the directory with the right ownership.
4. `/var/lib/icevirtue/jwt.secret`, the FHS location for persistent per-host application state, when it is writable.
5. `$XDG_STATE_HOME/icevirtue/jwt.secret`, defaulting to `~/.local/state/icevirtue/jwt.secret`, for an unprivileged run that cannot write under `/var/lib`.

The key is written `0600` inside a `0700` directory. Keep the key and database together when moving an installation. To rotate the key and invalidate every session, stop the service, remove the key, and restart. Upgrading from the old username-based JWT format requires everyone to sign in again even if the key is preserved.

The **tool config home** is where the spawned recon tools keep their own configuration and cache, such as `subfinder`'s `provider-config.yaml` and `nuclei`'s templates. It defaults to `/opt/icevirtue` and falls back to `$HOME` and then to a writable directory ICEvirtue can find, and `--tool-home` overrides it. Files land under `<tool-home>/.config/`. This is entirely independent of `--db-path`, and the resolved value is logged at startup. If you want API keys for `subfinder`'s paid sources, put them in `<tool-home>/.config/subfinder/provider-config.yaml`.

## Accounts, settings and roles

The Settings navigation tab opens a server-rendered page at `/settings`. Operators and Admins can open "User" settings at `/settings/user` to change their username or password. The current password is required, and a successful change revokes every session for that account. Viewers can see their role in Settings but cannot open or submit the account editor.

Admins can open `/settings/admin`, then Users or Server logs. Users supports account creation, role assignment, credential edits and permanent account deletion. Every saved edit, including a save without changed values, increments the account version and revokes all its sessions. Admins may edit themselves and are then returned to login. Deleting or demoting the last Admin is refused. User deletion removes sessions and notifications while preserving shared reconnaissance data.

Viewer permits reads of profiles, schedules, findings, assets and notifications. Operator adds profile creation, scheduling, deletion, scan execution, notification mutations and self-service account edits. Admin adds user administration and server logs. These rules are checked on the server. All authenticated API writes require Operator or Admin; login and logout are authentication operations available to every role. There is no per-profile ownership restriction in this version.

Existing accounts migrate once to Admin because the former provisioning command created administrators. New accounts default to Viewer in the model and admin form; the bootstrap CLI creates Admin accounts. The demo fixture is an Admin.

JWTs contain only an opaque account UUID, a random session ID, account version, issuer, audience and issue/not-before/expiry timestamps. The server pins HS256 and the session token type, checks every required claim, then checks the live account, version and session record in SQLite. Roles are read from the current account record. Legacy tokens are rejected. `--session-ttl` defaults to 24 hours and accepts one second through seven days. Logout revokes one session; account edits revoke all. SSE streams check revocation before sending data and every two seconds while idle.

Account pages are separate templates outside the public static tree. Forms use ordinary server POSTs with session-bound CSRF tokens, server validation and escaped HTML responses. Account management does not depend on client-side JavaScript. New passwords must meet the saved application policy: initially 8–26 Unicode characters, with an independent 72-byte UTF-8 cap. Existing passwords remain valid. Usernames must contain 3–64 letters, numbers, dots, underscores, @ or hyphens, beginning with a letter or number.

Server logs show the latest 2,000 process log entries, newest first, in pages of 100. Entries are capped at 16 KiB. The in-memory buffer resets on restart; normal process output remains available to the service manager. Logs are Admin-only and rendered as escaped text. SQL parameters, HTTP query strings and request bodies are not included by the new request/database logging configuration.

See [the implementation and verification report](docs/account-access.md) for the design rationale and scope of the access-control checks.

## HTTP API

Everything the dashboard does is available over HTTP. Authentication is a `POST` to `/api/login` with a JSON body containing `username` and `password`, which sets an `auth_token` cookie that every other endpoint requires.

| Method and path | What it does |
|---|---|
| `GET /login` | The login page. Redirects to `/` if you are already signed in. |
| `GET /` | The dashboard. Redirects to `/login` if you are not. |
| `POST /api/login` | Log in, sets the session cookie. Rate limited per client address. |
| `POST /api/logout` | Revoke the current session on the server and clear its cookie. |
| `GET /api/profiles` | Target profiles, paginated. |
| `GET /api/profiles/index` | Every profile as an id and a domain, unpaginated. This is what the dashboard's target picker reads, so it is not truncated to a page. |
| `POST /api/profiles` | Create a profile from `domain`, `schedule` and optional `mode`. |
| `DELETE /api/profiles/{id}` | Delete a profile and all of its findings. |
| `PUT /api/profiles/{id}/schedule` | Change a profile's schedule. |
| `POST /api/profiles/{id}/scan` | Force a scan now, returns immediately and runs in the background. |
| `GET /api/profiles/{id}/overview` | Profile-scoped Home summary: UTC scan/change times, exact asset and severity counts, eight Critical/High findings, and unique detected WAF names. |
| `GET /api/profiles/{id}/subdomains` | Subdomains found for the profile. |
| `GET /api/profiles/{id}/hosts` | Alive hosts, with status code, title, web server and IPs. |
| `GET /api/profiles/{id}/wafs?host=...` | Exact WAF names and successful-probe state for one node. |
| `GET /api/profiles/{id}/directories` | Directory and file findings. |
| `GET /api/profiles/{id}/vulnerabilities` | Nuclei findings. |
| `GET /api/profiles/{id}/vulnerabilities/severity-summary?host=...` | Exact nonzero Nuclei finding counts grouped by severity for one asset. |
| `GET /api/profiles/{id}/secrets` | Secrets found in JavaScript. |
| `GET /api/events` | Authenticated Server-Sent Events stream, including scan updates and notifications. Revoked sessions stop receiving events. |

Profile and finding list endpoints are paginated and answer with an envelope rather than a bare array:

```json
{
  "data": [ ... ],
  "page": { "page": 1, "size": 100, "total_rows": 4044, "total_pages": 41, "sort": "name-asc" }
}
```

The `page` object reports what the server actually did, which matters because it clamps: ask for `size=5000` and you get `"size": 1000` back, so a downgraded request is visible instead of silent. An unknown `sort` or `filter` falls back to the default and the effective value is echoed, so a stale bookmark still renders.

| Parameter | Meaning |
|---|---|
| `page` | 1-based. A page past the end is pulled back to the last one, and the corrected number is reported. |
| `size` | Rows per page. Clamped to 1000. Per-endpoint defaults: 25 for profiles, 100 for subdomains, hosts and directories, 50 for vulnerabilities and secrets. |
| `sort` | One of the endpoint's known orders. Every list has a deterministic total order, so paging cannot show a row twice or skip one. |
| `filter` | Subdomains only. Mirrors the dashboard's filter pills. |
| `host` | Vulnerabilities, directories, secrets and hosts. Scopes the response to one host, which is how the dashboard renders a single node. |

`limit` and `offset` are still accepted as aliases for `size` and `page`.

A subdomain row carries its own finding counts, a representative status code, and a `last_changed` timestamp, so a client does not have to correlate anything itself. `last_changed` advances only for a meaningful recon diff (a new or changed related observation), while `last_seen` remains the raw observation timestamp. Those counts stop at 1000 — the badge only needs to distinguish "none" from "a few" from "a lot" — while the exact total for one host is what `total_rows` reports when you scope to it with `host=`.

## Dashboard fixture data

Create a disposable database with two sample targets, changed and unchanged assets, Nuclei findings at several severity levels, directories, SecretHound and Mantra credential findings, and a demo login:

```sh
go run ./cmd/mockdata
go run . --db-path mock-dashboard.db
```

Sign in as `demo` with password `recon-demo`. The generated `mock-dashboard.db` and its WAL sidecars are ignored by Git. Run `go run ./cmd/mockdata --reset` to recreate it. The general Credentials tab shows both engines. Open the `app.acme.example.com` or `api.acme.example.com` node to inspect SecretHound risk, occurrences, description, and context. Mantra's unique finding is unattributed and appears only in the general tab; a duplicate Mantra finding is retained in the database but suppressed there. New fixtures use calendar schedules (daily and weekly), which the Profiles table shows with their time of day. Existing fixtures retain their stored `@every` interval until you recreate or edit them; the UI labels those as intervals without inventing a clock time.

To run the dev-only Chroma browser smoke suite against this disposable fixture, run `npm install` and `npx playwright install`, leave the dashboard running, then run `npm run test:ui`. The suite exercises Chromium, Firefox and WebKit at phone, tablet, desktop and short-landscape sizes; use `ICEVIRTUE_SMOKE_URL` if the server is not at `http://127.0.0.1:8888`. Do not point the suite at a production database: one test creates and removes a temporary profile.

## Troubleshooting

Start with the preflight block ICEvirtue logs at startup. It names the resolved tool config home and lists which required tools were found, which are not needed given your flags, and which are missing from `PATH` along with the `PATH` it actually searched. A missing tool is by far the most common cause of a stage failing.

Next look at the per-stage summary. It tells you which tools contributed results, which failed, which were skipped and why, and how many unique results the stage produced once every source was merged. A stage that reports `1 of 3 tool(s)` did useful work with two tools broken, and the summary names them.

When an external tool does fail, the log entry names the resolved binary, the exact arguments, the exit status, how long it ran, the `HOME` it was given, and the tail of **both** its output streams. That last detail matters, because several of these tools report fatal startup errors on standard output rather than standard error, so a report that only showed standard error would leave you with a blank message.

Every tool also has a wall clock budget, and one that exceeds it is killed along with any child processes it spawned. The log says `timed out after` with the budget that was hit, so a hung tool cannot leave a profile stuck in the scanning state forever. A tool killed this way keeps whatever it had already emitted, marked `PARTIAL` in the stage summary, rather than losing the run.

If the dashboard shows a `halted:` status, the reason is in the status itself and the matching log block explains it in full. `halted: no subdomains found from any source` almost always means the target domain is wrong. `halted: no host answered HTTP` means discovery worked but nothing is reachable, which is worth checking your egress and DNS for before you blame the target.

### Tool output storage

ICEvirtue writes captured tool stdout to private temporary files and parses it sequentially after each process exits, including usable output from failed or timed-out tools. Files are closed and removed after parsing. Stdout and stderr diagnostic excerpts remain capped at 64 KiB each. SecretHound and Waymore write their findings to explicit files, so their console output is retained only for diagnostics.

Temporary files follow `TMPDIR` (or the operating system default). Set `TMPDIR` to a writable, disk-backed directory with sufficient free space to move output storage away from RAM; a tmpfs-backed `/tmp` still consumes memory. Disk I/O can increase scan time, disk exhaustion causes reported tool errors, and abrupt application termination can leave temporary files behind. Captured stdout is capped at 1 GiB per tool, and the worker cancels a scan below 64 MiB of filesystem free space. Heap use still depends on the largest record, accumulated findings, and deduplication state. SecretHound's JSON results are still loaded as an array.


## Disclaimer

ICEvirtue is a work-in-progress and it is mainly created for my specific needs. Although I might add specific functionalities per request, you are much welcome to fork this project and use it as a baseline to start your own if you have specific needs or visions. This project is also created with the help of AI, so take much care when exposing it for access over the Net.

That being said, it is being developed with ample focus on security, so you don't get ass whooped by another 'runner while you are asleep. I super appreciate bug reports and vulnerability disclosures, feel absolutely free to mess around with this project in your lab environment and report anything you may find. I will absolutely love to hear and fix such bugs.
