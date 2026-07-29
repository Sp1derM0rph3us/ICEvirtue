# ICEvirtue

![](https://github.com/Sp1derM0rph3us/ICEvirtue/blob/dev/ICEvirtue_login.png)
ICEvirtue is the netrunner's most essential tool. It executes a standardized reconnaissance and enumeration pipeline and stores the results inside **target profiles**, allowing netrunners to focus on what really matters: cracking those defenses.

You register a domain once, tell ICEvirtue how often to look at it, and it keeps looking. Every run is diffed against everything it has seen before for that profile, so the dashboard tells you what is *new* rather than dumping the same ten thousand subdomains on you every night. Findings are grouped per profile into subdomains, alive hosts, directories, vulnerabilities and secrets, and the dashboard updates itself live over Server-Sent Events while a scan is running.

Two binaries make up the project. `ICEvirtue` is the engine and the web dashboard, and `ICEvirtue-admin` is the small companion tool you use to create dashboard users, because there is no default account.

## How The Pipeline Works

The application follows a continuous reconnaissance workflow separated into five stages, each feeding the next.

**Stage 01, Basic Recon.** ICEvirtue runs [Subfinder](https://github.com/projectdiscovery/subfinder) for passive subdomain discovery. In Full Mode it also passes `-all` to Subfinder and runs [Amass](https://github.com/owasp-amass/amass), unless you started the engine with `--skip-amass`. If you supplied `--dnsx-list`, it additionally runs [DNSX](https://github.com/projectdiscovery/dnsx) once per wordlist for active DNS bruteforcing. Results from all three sources are merged and de-duplicated before anything else happens.

**Stage 02, Web Validation.** Every discovered name is probed with [HTTPX](https://github.com/projectdiscovery/httpx) to collect status code, page title, web server and resolved IPs. All subdomains are saved to the profile whether they are alive or not, but only hosts answering `200`, `301`, `302` or `307` are carried forward, which keeps the expensive later stages off dead or inaccessible assets.

**Stage 03, Directory and File Fuzzing.** If you supplied `--directory-list`, a built-in concurrent fuzzer walks the carried-forward hosts. You can pass several wordlists and the engine merges and de-duplicates them, so overlapping lists cost you nothing. Requests do not follow redirects, and a path is recorded when it answers `200`, `301`, `302`, `403` or `405`. Without `--directory-list` the stage is skipped.

**Stage 04, Vulnerability Scanning.** Unless you passed `--skip-nuclei`, [Nuclei](https://github.com/projectdiscovery/nuclei) is run against the carried-forward hosts to identify vulnerabilities and misconfigurations. Template ID, matched URL, severity, name and description are stored per finding.

**Stage 05, Secret Hunting.** Finally ICEvirtue hunts hard-coded secrets and credentials in historical and current JavaScript. It collects candidate URLs from [Gau](https://github.com/lc/gau), validates the historical ones with HTTPX, crawls the live hosts with [Katana](https://github.com/projectdiscovery/katana), extracts script references with [Subjs](https://github.com/lc/subjs), and then feeds the resulting set of live JS files to [Mantra](https://github.com/brosck/mantra) and [SecretFinder](https://github.com/m4ll0k/SecretFinder). This stage is best effort: if one of those tools is missing or fails, the failure is logged and the rest of the stage still runs.

### When A Run Stops Early

Decisions about stopping are made per stage, never per tool. A stage attempts every tool available to it, merges whatever came back, saves that to the profile, and only then asks whether the run still has enough to continue. No single tool can end a run: if Subfinder cannot execute, Amass and `dnsx` still get their turn, and whatever they find carries the run forward.

The rule for whether a stage can stop the run at all is simply whether a later stage consumes its output. Discovery and validation produce the input everything else depends on, so those two can stop a run. Fuzzing, vulnerability scanning and secret hunting are leaves, since nothing reads their findings, so they can only run or be skipped. A leaf stage failing outright never ends the run.

That leaves exactly two conditions that stop a run, and both mean there is genuinely nothing left to work with:

Discovery produced no subdomains at all, meaning every source either failed or came back empty. Note that this is checked against the **merged** set, so Subfinder finding names keeps the run going even when Amass and `dnsx` each contribute nothing. If you see this halt, the most likely explanation is a typo in the target domain.

Validation found no host that answered HTTP. Every later stage needs a live host, and stage 05 validates its archived URLs against live hosts too, so there is nothing productive left to attempt.

Anything else is reported and moved past. A tool that is missing, errors out, or exceeds its time budget is recorded as a failure for that stage, and a stage with no work to do is recorded as skipped with the reason. Skipping is not failing: leaving out `--dnsx-list` or passing `--skip-nuclei` shows up as `skipped`, not as a problem.

Because these tools stream their results, a tool that dies partway through still contributes everything it emitted first. Those runs are marked `PARTIAL` in the stage summary, so a Nuclei scan killed at the end of its two hour budget keeps the findings it had already reported rather than throwing the whole scan away. The same applies when a run halts: everything collected before the halt is saved to the profile and appears in the dashboard, so a run that stops at validation still leaves you its subdomains.

Each stage logs a summary showing exactly which tools contributed what:

```
[+] [Target: example.com] Stage 01 Discovery: 4044 unique result(s) from 2 of 3 tool(s)
      subfinder      ok         3987
      amass          FAILED        0  amass not found: install it and make sure it is on PATH (searched: ...)
      dnsx[wl1.txt]  ok           57
      dnsx[wl2.txt]  skipped         no --dnsx-list was provided
```

## Requirements

You need Go 1.25 or newer to build, and **all of the external tools listed above have to be installed and reachable on the `PATH` of the user ICEvirtue runs as**. This is the single most common reason a fresh install does not work, so ICEvirtue prints a preflight summary at startup telling you exactly which tools it found and which it could not, before any scan is ever triggered. Check that line first when a stage fails.

Not every tool is needed in every configuration. Which ones ICEvirtue actually requires depends on the flags you start it with:

| Tool | Stage | Needed when |
|---|---|---|
| `subfinder` | 01 | always |
| `amass` | 01 | unless `--skip-amass` |
| `dnsx` | 01 | only if `--dnsx-list` is given |
| `httpx` | 02, 05 | always |
| `nuclei` | 04 | unless `--skip-nuclei` |
| `gau`, `katana`, `subjs`, `mantra`, `secretfinder.py` | 05 | always attempted, failures are non-fatal |

Stage 03 needs no external tool at all, since the fuzzer is built in.

Note that `secretfinder.py` has to be on `PATH` under exactly that name and be directly executable, which usually means giving it a shebang and a `chmod +x`.

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
ICEvirtue --tool-paths httpx=/usr/bin/httpx-toolkit,nuclei=/opt/tools/nuclei
```

An explicit `--tool-paths` entry is used as given, with no discovery and no probing.

Do not solve this by removing `python3-httpx`. On a typical Kali or Parrot install `python3-dnspython` depends on it, and removing it takes dnspython with it. If you would rather fix it at the system level than pass a flag, symlink the real binary somewhere that precedes `/usr/bin` on your `PATH`:

```Shell
sudo apt install httpx-toolkit
sudo ln -s /usr/bin/httpx-toolkit /usr/local/bin/httpx
```

One more thing worth knowing: `katana`, `gau`, `subjs` and `mantra` are not packaged on Debian-family systems at all, so they come from `go install` and land in `$GOPATH/bin`, usually `~/go/bin`. That directory is not on a systemd service's `PATH`, so either add it to `Environment=PATH=` in the unit or copy those binaries into `/usr/local/bin`.

## Installation

Build both binaries and drop them somewhere on the system `PATH`:

```Shell
sudo su
# type in sudo password...

git clone https://github.com/Sp1derM0rph3us/ICEvirtue.git
cd ICEvirtue
go build -o /usr/bin/ICEvirtue main.go            # the engine and dashboard
go build -o /usr/bin/ICEvirtue-admin cmd/admin/main.go   # user management
chmod 775 /usr/bin/ICEvirtue*
```

If you installed any of the recon tools with `go install`, they landed in `$GOPATH/bin` (usually `~/go/bin`). That directory is on your interactive `PATH` but almost certainly not on the `PATH` of a service, so either copy those binaries into `/usr/bin` too or set the service `PATH` explicitly as shown further down.

## Setting Up

ICEvirtue needs three things in place before it is useful: a working directory containing the `web` folder, a database, and at least one dashboard user.

The `web` folder holds the dashboard templates and static assets, and ICEvirtue loads them from a path relative to its working directory. When you run the engine from a checkout this already works. When you run it from anywhere else, copy the folder next to wherever the application will live:

```Shell
mkdir -p /opt/icevirtue
cp -r ./ICEvirtue/web /opt/icevirtue
```

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

The simplest useful invocation gives the engine wordlists for both active DNS bruteforcing and directory fuzzing, and turns on per-finding logging:

```Shell
ICEvirtue --directory-list /path/to/wl1,/path/to/wl2 --dnsx-list /path/to/wl1,/path/to/wl2 --verbose
```

That runs the full pipeline. The dashboard listens on port `8888/tcp` by default, so open `http://localhost:8888` and log in with the user you created. If that port is taken, or you simply prefer another one, use `--api-port`:

```Shell
ICEvirtue --api-port 2077
```

You can trim the pipeline down when a target's infrastructure is fragile, when your VPS is small, or when you are just testing. `--skip-amass` and `--skip-nuclei` each remove one stage's heaviest tool and can be combined freely:

```Shell
ICEvirtue --directory-list /path/to/wl1 --skip-nuclei --skip-amass
```

Two stages are opt-in rather than opt-out. Leaving out `--dnsx-list` skips active DNS bruteforcing, and leaving out `--directory-list` skips directory fuzzing entirely. Both log a line saying so, so a skipped stage never looks like a silent failure.

### ICEvirtue Flag Reference

| Flag | Default | What it does |
|---|---|---|
| `--api-port` | `8888` | TCP port the web dashboard listens on. |
| `--db-path` | `icevirtue.db` | Path to the SQLite database. Must match the path used by `ICEvirtue-admin`. |
| `--directory-list` | *(empty)* | Comma-separated absolute paths to wordlists for directory fuzzing. Multiple lists are merged and de-duplicated. Omit to skip stage 03. |
| `--dnsx-list` | *(empty)* | Comma-separated absolute paths to wordlists for active `dnsx` bruteforcing, used in Full Mode only. `dnsx` runs once per list. Omit to skip DNS bruteforcing. |
| `--jwt-secret` | *(auto)* | Path to the key that signs dashboard session cookies. See "Where State Lives" for how the default is chosen. |
| `--skip-amass` | `false` | Skip Amass during stage 01. Everything else in that stage still runs. |
| `--skip-nuclei` | `false` | Skip stage 04 entirely. |
| `--tool-home` | *(auto)* | Directory the spawned recon tools use for their own config, defaulting to `/opt/icevirtue` and falling back to `$HOME`. See "Where State Lives". |
| `--tool-paths` | *(empty)* | Comma-separated `name=path` overrides pinning a tool to an exact binary, for example `httpx=/usr/bin/httpx-toolkit`. Skips discovery and the identity probe for that tool. |
| `--verbose` | `false` | Log every individual finding as it is diffed, marking each as new or already known, instead of only the per-stage totals. |
| `--wide-targets` | `false` | Widen which hosts reach stages 03 to 05. See below. |

By default only hosts answering `200`, `301`, `302` or `307` are handed to fuzzing, Nuclei and secret hunting. `--wide-targets` replaces that with everything HTTPX reported except a plain `404`, which brings `401`, `403`, `405`, `500` and `503` hosts into scope. A `403` on `/` tells you nothing about what `/admin` returns, and finding exactly that is the point of directory fuzzing, so the wide filter is usually what you want on a target you are allowed to be thorough with. It costs scan time proportional to how many extra hosts it lets through, and the stage log tells you how many that was:

```
[*] [Target: example.com] Target filter wide (any status except 404) selected 47 of 52 alive host(s)
```

Paths given to `--directory-list` and `--dnsx-list` should be absolute, since they are read relative to the working directory otherwise. Both accept a trailing comma, and empty entries are ignored.

## ICEvirtue-admin Reference

`ICEvirtue-admin` exists only to seed dashboard accounts. It takes a single subcommand, `create`:

```Shell
ICEvirtue-admin create --username 'netrunner' --password 'super-secret-password' [--db-path /opt/icevirtue/icevirtue.db]
```

| Flag | Default | What it does |
|---|---|---|
| `--username` | *(required)* | Username for the new dashboard account. |
| `--password` | *(required)* | Password for the account. Stored as a bcrypt hash, never in plain text. |
| `--db-path` | `./icevirtue.db` | Database to write the account into. Created and migrated if it does not exist. |

Both `--username` and `--password` are mandatory, and usernames are unique, so creating an account that already exists fails rather than overwriting it. There is currently no subcommand for listing, editing or deleting users, so managing an existing account means editing the `users` table directly.

## Running As A systemd Service

A systemd system service gets **no `$HOME`** and defaults to `WorkingDirectory=/`. That combination breaks the projectdiscovery tools (`subfinder`, `httpx`, `dnsx`, `nuclei`, `katana`), because they resolve their config directory from `$XDG_CONFIG_HOME`, then `$HOME/.config`, and finally relative to the working directory. With no writable candidate they exit immediately, printing `open subfinder/config.yaml: no such file or directory`. The same happens if `$HOME` is set but not writable by the service user, which is what you get from a system account created without a home directory, or from `ProtectHome=`.

ICEvirtue defends itself against this by giving every tool it spawns a `HOME` it has verified is writable, so it works out of the box. You should still pin the environment explicitly rather than rely on a fallback:

```ini
[Unit]
Description=ICEvirtue continuous reconnaissance engine
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
StateDirectory=icevirtue
WorkingDirectory=/opt/icevirtue
Environment=HOME=/opt/icevirtue
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/bin/ICEvirtue --db-path /opt/icevirtue/icevirtue.db --api-port 8888 --directory-list /path/to/wl1 --dnsx-list /path/to/wl1
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`WorkingDirectory` matters twice over, since it is where the `web` folder is looked up. `StateDirectory=icevirtue` makes systemd create `/var/lib/icevirtue` with the right ownership and hand its path to the process, which is where the session signing key ends up. If you add `User=` to run as a dedicated account, make sure that account can read the wordlists and write both the database directory and `/opt/icevirtue`.

## Where State Lives

ICEvirtue keeps three separate pieces of state, and each can be relocated.

The **database** is a single SQLite file holding users, profiles and every finding. It is controlled by `--db-path` and defaults to `icevirtue.db` in the working directory. WAL mode is enabled, so expect `icevirtue.db-wal` and `icevirtue.db-shm` alongside it. Back up all three together, or checkpoint first.

The **session signing key** is 64 random bytes generated on first run and reused afterwards, so it has to persist somewhere stable. Restarting with a different key logs everyone out. Because the location has to work both for a service and for a casual terminal run, ICEvirtue picks it in this order:

1. `--jwt-secret /path/to/key`, when you pass it.
2. An existing `./jwt.secret` in the working directory, so upgrading from an older build keeps your current key instead of invalidating every session.
3. `$STATE_DIRECTORY`, which systemd sets from `StateDirectory=icevirtue`. This is the recommended setup, since systemd creates the directory with the right ownership.
4. `/var/lib/icevirtue/jwt.secret`, the FHS location for persistent per-host application state, when it is writable.
5. `$XDG_STATE_HOME/icevirtue/jwt.secret`, defaulting to `~/.local/state/icevirtue/jwt.secret`, for an unprivileged run that cannot write under `/var/lib`.

The key is written `0600` inside a `0700` directory. Copy it if you want existing sessions to survive a migration, and delete it if you want to invalidate every session, in which case everyone simply logs in again.

The **tool config home** is where the spawned recon tools keep their own configuration and cache, such as `subfinder`'s `provider-config.yaml` and `nuclei`'s templates. It defaults to `/opt/icevirtue` and falls back to `$HOME` and then to a writable directory ICEvirtue can find, and `--tool-home` overrides it. Files land under `<tool-home>/.config/`. This is entirely independent of `--db-path`, and the resolved value is logged at startup. If you want API keys for `subfinder`'s paid sources, put them in `<tool-home>/.config/subfinder/provider-config.yaml`.

## Using The Dashboard

The web interface is straightforward. You add a target domain, for instance `hackerone.com`, and choose how often ICEvirtue should scan it: every day, week, month or year, at a time of day you pick. Every profile created through the dashboard runs in Full Mode, so the breadth of the pipeline is controlled by the engine flags rather than per profile.

Scheduling follows the **system clock of the machine ICEvirtue runs on**, and there is currently no way to set a different timezone in the application. If you are hosting on a VPS, check what the server's clock is set to, otherwise your scans will fire at a different local time than you intended.

Under the hood, the schedules the dashboard produces are human-readable strings such as `every day at 14:30`. The API also accepts `@every 12h` style intervals and raw cron expressions, and because the scheduler is second-granular a raw cron expression needs six fields (`seconds minutes hours day-of-month month day-of-week`) rather than the usual five.

Once a scan starts, the "Discoveries" tab fills in as soon as the initial recon phase finishes, and each later stage complements the existing findings as it completes. Click a finding to see its details, or the icon at the far right of its row to open the asset itself. Secrets live in their own tab inside "Discoveries", and the "Select Profile" drop-down switches targets. The dashboard is updated live, so you never need to refresh to see a target flip between scanning and idle, or to see new findings appear.

You can also force a scan outside its schedule from the dashboard. A profile that is already scanning refuses a second concurrent run rather than doubling up, and the scan lock is released automatically when the run finishes, including when it fails.

The "Last Run" column summarises how each profile's most recent run ended, so you do not have to read the service log to notice a problem. A healthy run reads `completed`. A run where some tool fell over reads `completed, amass failed in Stage 01 Discovery`, or `completed, 3 tools failed` when more than one did. A run that stopped early reads `halted:` followed by the reason, highlighted in red, and remember that a halted run still saved everything it collected before stopping.

## HTTP API

Everything the dashboard does is available over HTTP. Authentication is a `POST` to `/api/login` with a JSON body containing `username` and `password`, which sets an `auth_token` cookie that every other endpoint requires.

| Method and path | What it does |
|---|---|
| `POST /api/login` | Log in, sets the session cookie. |
| `POST /api/logout` | Clear the session cookie. |
| `GET /api/profiles` | List all target profiles. |
| `POST /api/profiles` | Create a profile from `domain`, `schedule` and optional `mode`. |
| `DELETE /api/profiles/{id}` | Delete a profile and all of its findings. |
| `PUT /api/profiles/{id}/schedule` | Change a profile's schedule. |
| `POST /api/profiles/{id}/scan` | Force a scan now, returns immediately and runs in the background. |
| `GET /api/profiles/{id}/subdomains` | Subdomains found for the profile. |
| `GET /api/profiles/{id}/hosts` | Alive hosts, with status code, title, web server and IPs. |
| `GET /api/profiles/{id}/directories` | Directory and file findings. |
| `GET /api/profiles/{id}/vulnerabilities` | Nuclei findings. |
| `GET /api/profiles/{id}/secrets` | Secrets found in JavaScript. |
| `GET /api/events` | Server-Sent Events stream of `profile_update` and `discovery_update` events. |

The five finding endpoints are paginated with `limit` and `offset` query parameters. `limit` defaults to 250 and is capped at 1000.

## Troubleshooting

Start with the preflight block ICEvirtue logs at startup. It names the resolved tool config home and lists which required tools were found, which are not needed given your flags, and which are missing from `PATH` along with the `PATH` it actually searched. A missing tool is by far the most common cause of a stage failing.

Next look at the per-stage summary. It tells you which tools contributed results, which failed, which were skipped and why, and how many unique results the stage produced once every source was merged. A stage that reports `1 of 3 tool(s)` did useful work with two tools broken, and the summary names them.

When an external tool does fail, the log entry names the resolved binary, the exact arguments, the exit status, how long it ran, the `HOME` it was given, and the tail of **both** its output streams. That last detail matters, because several of these tools report fatal startup errors on standard output rather than standard error, so a report that only showed standard error would leave you with a blank message.

Every tool also has a wall clock budget, and one that exceeds it is killed along with any child processes it spawned. The log says `timed out after` with the budget that was hit, so a hung tool cannot leave a profile stuck in the scanning state forever. A tool killed this way keeps whatever it had already emitted, marked `PARTIAL` in the stage summary, rather than losing the run.

If the dashboard shows a `halted:` status, the reason is in the status itself and the matching log block explains it in full. `halted: no subdomains found from any source` almost always means the target domain is wrong. `halted: no host answered HTTP` means discovery worked but nothing is reachable, which is worth checking your egress and DNS for before you blame the target.

## Disclaimer

ICEvirtue is a work-in-progress and it is mainly created for my specific needs. Although I might add specific functionalities per request, you are much welcome to fork this project and use it as a baseline to start your own if you have specific needs or visions. This project is also created with the help of AI, so take much care when exposing it for access over the Net.

That been said, it is being developed with ample focus on security, so you don't get ass whooped by another 'runner while you are asleep. I super appreciate bug reports and vulnerability disclosures, feel absolutely free to mess around with this project in your lab environment and report anything you might find. I will absolutely love to hear and fix such bugs.
