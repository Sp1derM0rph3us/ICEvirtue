# ICEvirtue — Code Review Report (Run 1: correctness & general-usage bugs)

**Scope:** Full codebase QA pass focused on functional correctness, unintended behavior, and general code-quality bugs — *not* security vulnerabilities (that is a separate pass).
**Baseline:** `go build ./...`, `go vet ./...`, and `go test ./...` all pass cleanly on the reviewed tree (branch `dev`).
**Method:** Static reading of every Go source file plus the dashboard's inline JS, cross-referenced against the tests that pin each mechanism's contract. Two suspected storage/serialization bugs were **empirically probed** with throwaway tests before being ruled out (see [Appendix A](#appendix-a--things-verified-as-correct)).

Findings are ordered by severity. Each carries a root-cause analysis and, where the fix is deterministic, the concrete change.

---

## Severity summary

| # | Severity | Area | One-line |
|---|----------|------|----------|
| 1 | **High** | Discovery (dnsx) | `-resp-only` stores resolved **IPs instead of the brute-forced subdomain names**, defeating the feature |
| 2 | Medium | Validation (WAF) | WAF stage has no aggregate time budget and probes *every* alive host; can hold the scan lock for hours |
| 3 | Medium | Secret hunting | `isJSFile` uses substring match, misclassifying `.jsp`/`.json5`/`*.js.map`/query-strings as JS |
| 4 | Low | Exec harness | A single tool output line > 1 MB aborts the scanner and silently drops the rest of the stream |
| 5 | Low | Waymore index | A hash prefix shared by two saved files drops *both* captures |
| 6 | Low | Pagination | Legacy `offset` past the end is not clamped; `page` in the envelope can exceed `total_pages` |
| 7 | Low | Profiles API | `mode` is never validated; any typo silently degrades a scan to passive |
| 8 | Low | Mantra parser | Line split on `" ["` + trailing `]` strip mis-parses values/URLs containing those tokens |
| 9 | Info | mockdata | SecretHound fixtures are seeded *after* the live-evidence migration, so `SeenLive` stays false |

---

## 1. HIGH — `dnsx -resp-only` discards the discovered subdomain names

**Location:** [`internal/engine/dnsx.go:22`](internal/engine/dnsx.go#L22) (and the parser at [`dnsx.go:29`](internal/engine/dnsx.go#L29))

```go
args := []string{"-silent", "-d", profile.Domain, "-w", wordlistPath, "-resp-only"}
```

**Root cause.** In projectdiscovery's `dnsx`, the default output for `-d <domain> -w <wordlist>` bruteforce mode is the **resolved name** (the FQDN that answered). `-resp-only` replaces that with *only the DNS response record value* — i.e. the **A-record IP address**. So for a candidate `secret-admin.example.com` that resolves to `203.0.113.9`, the tool emits `203.0.113.9`, and `parseDnsxOutput` collects that IP. The name that was actually discovered — the entire point of DNS bruteforcing — is thrown away.

**Downstream damage.**
- The subdomains table is populated with bare IPs instead of hostnames. The code even accommodates this (`hostkey.Normalize` special-cases IPs; `internal/api/subdomains.go` ships an `ipPredicate`/IP filter), which masks the problem rather than fixing it.
- Those IPs are then merged into the stage-01 set and fed to `httpx` in stage 02. Probing a raw IP hits the server's *default* virtual host, not the vhost that the brute-forced name would have selected — so even the alive-host data is for the wrong target.
- Net effect: the `--dnsx-list` feature produces a bag of IPs and never records a single brute-forced subdomain name.

**Evidence it is unintended.** The pipeline test stubs `dnsx` to echo a **name** (`small.example.com`, `big.example.com`) — [`internal/engine/pipeline_test.go:351`](internal/engine/pipeline_test.go#L351) — and asserts those names flow through as subdomains. The author's mental model is clearly "dnsx returns names," which directly contradicts the `-resp-only` flag that is actually passed. Because the tool is stubbed, the test cannot catch the mismatch.

**Fix (deterministic).** Drop `-resp-only` so dnsx prints the resolved names:

```go
args := []string{"-silent", "-d", profile.Domain, "-w", wordlistPath}
```

`-silent` already suppresses banners, and default output is one resolved FQDN per line, which is exactly what `parseDnsxOutput` expects. (If the org also wants the resolved IPs recorded, that is a separate feature — capture them with `-a -resp` and parse both columns, but do **not** let IPs replace names.) Recommend confirming against the installed dnsx version with `echo www | dnsx -d example.com -silent` before merging.

---

## 2. MEDIUM — WAF detection stage has no aggregate budget and runs against every alive host

**Location:** [`internal/engine/wafw00f.go:74`](internal/engine/wafw00f.go#L74) (`RunWAFDetection`), invoked at [`internal/engine/engine.go:147`](internal/engine/engine.go#L147)

**Root cause.** `RunWAFDetection` is handed the **full** alive-host set from stage 02 (not the `targetHosts` subset), and iterates it with a fixed `workers = 4` pool. Each `detectWAF` call spawns a `wafw00f` process capped at `timeoutWAFW00F = 90 * time.Second` ([`exec.go:37`](internal/engine/exec.go#L37)). There is **no stage-level deadline** on the aggregate.

Every other heavy tool (subfinder, amass, httpx, nuclei, …) has a single wall-clock budget precisely so "a hung tool cannot leave a profile stuck in the scanning state" ([`exec.go:29-31`](internal/engine/exec.go#L29)). WAF detection is the one stage that bypasses this: its worst case is `(len(hosts) / 4) * 90s`. For a profile with, say, 8,000 alive hosts where a meaningful fraction hit the per-host cap, the stage can run for **hours to days**, and `is_scanning = true` is held the entire time because the lock is only released when `OrchestrateScan` returns.

This is not the same as the intentional "probe every endpoint regardless of status code" design (which is fine and documented). The gap is the *missing outer bound*.

**Suggested fix.** Give the stage its own budget the way the tool wrappers do — wrap the worker pool in a `context.WithTimeout` and stop dispatching new jobs once it fires (recording the run as `PARTIAL`, consistent with the rest of the pipeline). A few minutes is a reasonable cap for a best-effort enrichment step. Raising `workers` also helps but does not bound the tail on its own.

---

## 3. MEDIUM — `isJSFile` substring match over-selects non-JS URLs

**Location:** [`internal/engine/source-review.go:36`](internal/engine/source-review.go#L36)

```go
func isJSFile(url string) bool {
    for _, ext := range jsExtensions { // ".js", ".json", ".ts", ".tsx"
        if strings.Contains(url, ext) {   // <-- substring, not extension
            return true
        }
    }
    return false
}
```

**Root cause.** `strings.Contains` matches the extension token *anywhere* in the URL. Consequences: `https://host/app.jsp` contains `.js`; `https://host/x.json5` contains `.json`; `https://host/main.js.map` contains `.js`; `https://host/p?file=a.ts` contains `.ts`; and a hostname like `foo.json.example.com` contains `.json`. All are wrongly treated as JavaScript and forwarded from Katana crawl results into the secret scanners.

The impact is bounded (SecretHound/Mantra tolerate junk input), so this is quality rather than correctness — but it is also **inconsistent with the sibling function** `isArchiveFileURL` ([`archive.go:85`](internal/engine/archive.go#L85)), which does it correctly by parsing the URL and testing `strings.HasSuffix(u.Path, ext)`.

**Fix (deterministic).** Mirror `isArchiveFileURL`:

```go
func isJSFile(raw string) bool {
    u, err := url.Parse(raw)
    if err != nil {
        return false
    }
    path := strings.ToLower(u.Path)
    for _, ext := range jsExtensions {
        if strings.HasSuffix(path, ext) {
            return true
        }
    }
    return false
}
```

(Consider extracting one shared helper so the two cannot drift again.)

---

## 4. LOW — A tool output line larger than 1 MB aborts the stream parse

**Location:** [`internal/engine/exec.go:266-274`](internal/engine/exec.go#L266) (`newLineScanner`)

```go
scanner := bufio.NewScanner(out)
scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // max token = 1 MiB
```

**Root cause.** `bufio.Scanner` returns `bufio.ErrTooLong` and stops permanently when a single line exceeds the max token size. Nuclei/httpx emit JSONL where one record can carry a large matched-response or description; a finding over 1 MiB will not only be dropped — it terminates the scan, so **every subsequent line in that tool's output is lost** too. The parsers then log "Stopped reading … output early" and return only what preceded the oversized line.

This is an edge case (most lines are small) and the raised-from-64 KiB limit already reflects awareness of long lines, so severity is low. If robustness matters here, switch the hot JSONL readers to `bufio.Reader.ReadString('\n')` (or `ReadBytes`), which skips over an oversized line instead of aborting the whole stream.

---

## 5. LOW — Waymore captures are dropped when two saved files share a numeric hash prefix

**Location:** [`internal/engine/archive.go:162`](internal/engine/archive.go#L162)

```go
if !ok || !archiveHashPattern.MatchString(hash) || len(byHash[hash]) != 1 {
    bad++
    continue
}
```

**Root cause.** Files are grouped by the numeric prefix before the first `.` ([`archive.go:134`](internal/engine/archive.go#L134)). The index reader requires `len(byHash[hash]) == 1` to map a capture to a file. If waymore ever writes two responses that share the same numeric prefix but differ by extension (e.g. `123.js` and `123.json`), the group size is 2 and **both** captures are counted as `bad` and dropped — the archived-file secret findings for those responses vanish with only an aggregate "invalid or unmappable" count to show for it.

Whether waymore can actually collide prefixes depends on its file-naming scheme; the guard is defensive but fails *closed on both* rather than disambiguating. Low severity/likelihood. If it proves reachable, key the map on the full filename (prefix+extension) taken from the index line rather than on the prefix alone.

---

## 6. LOW — Legacy `offset` past the end is not clamped

**Location:** [`internal/api/pagination.go:139-143`](internal/api/pagination.go#L139)

```go
if q.hasLegacyOffset {
    page = q.legacyOffset/q.Size + 1
    offset = q.legacyOffset          // <-- not clamped against total
} else {
    if page > totalPages { page = totalPages }
    ...
}
```

**Root cause.** The page-number path pulls an out-of-range page back to `totalPages` and reports the correction; the `limit`/`offset` compatibility path deliberately honors the offset "verbatim." The side effect is that `GET …?offset=999999` on a 40-row table returns an empty `data` array while the envelope's `page` reports a number far beyond `total_pages`, which is exactly the "partial vs. complete is indistinguishable" confusion the pagination envelope exists to prevent. It is documented as intentional, so this is a consistency nit rather than a defect — flagged so the decision is explicit. If you want parity, clamp `offset` to `totalRows` before computing the reported page.

---

## 7. LOW — `mode` is accepted without validation

**Location:** [`internal/api/profiles.go:109-111`](internal/api/profiles.go#L109), consumed at [`internal/engine/engine.go:215`](internal/engine/engine.go#L215)

**Root cause.** `createProfile` only defaults an empty `mode` to `"full"`; any non-empty value is stored as-is. `stageDiscovery` then treats **anything that is not exactly `"full"`** as passive (`if profile.Mode != "full"` skips amass and dnsx). So a client that sends `mode: "Full"`, `mode: "aggressive"`, or a typo silently gets a passive scan — amass and DNS bruteforce quietly never run, with nothing on the profile or in the log to say why. The dashboard always sends `"full"`, so this is latent, but the API is documented as public.

**Fix (deterministic).** Reject unknown modes at the handler:

```go
switch req.Mode {
case "":
    req.Mode = "full"
case "full", "passive":
    // ok
default:
    http.Error(w, "invalid mode", http.StatusBadRequest)
    return
}
```

---

## 8. LOW — Mantra line parser mis-handles values/URLs containing its delimiters

**Location:** [`internal/engine/source-review.go:230-235`](internal/engine/source-review.go#L230)

```go
source, bracketed, ok := strings.Cut(strings.TrimPrefix(line, "[+] "), " [")
...
value := strings.TrimSpace(strings.TrimSuffix(bracketed, "]"))
```

**Root cause.** Mantra emits `[+] <source-url> [<secret>]` as free text (no JSON option). The parser splits on the first `" ["` and strips one trailing `]`. A source URL that itself contains `" ["`, or a secret value containing `]`, is parsed incorrectly (wrong source/value boundary, or a truncated value). This is inherent to scraping Mantra's human-readable output and is low-likelihood, but worth a note: `strings.Cut` on the **last** `" ["` (via `strings.LastIndex`) would be marginally more robust for the common case of a clean trailing `[secret]`.

---

## 9. INFO — mockdata SecretHound fixtures never get `SeenLive = true`

**Location:** [`cmd/mockdata/main.go:32`](cmd/mockdata/main.go#L32) (migrations) vs. [`main.go:44-46`](cmd/mockdata/main.go#L44) / `createSecret` at [`main.go:188`](cmd/mockdata/main.go#L188)

**Root cause.** `RunDataMigrations()` runs first and marks `secretLiveEvidenceV1` applied; the SecretHound fixtures are `Create`d afterward with `SeenLive` left at its zero value (`false`). Because the migration already ran, nothing backfills them. The README describes real SecretHound findings as live evidence, so the fixture under-represents that state (the "live" link/badge won't render for the seeded rows). Fixture-only, no product impact — set `SeenLive: true` on the seeded SecretHound findings to match reality.

---

## Appendix A — Things verified as *correct* (candidate bugs ruled out)

Recorded so the same ground isn't re-tilled next pass. Both were checked with throwaway tests against the real GORM/SQLite stack, not by reasoning alone.

- **Mixed timestamp formats (`CURRENT_TIMESTAMP` vs `autoCreateTime`).** The `diff*` update paths write `last_seen` via `gorm.Expr("CURRENT_TIMESTAMP")`, while inserts use GORM's `autoCreateTime`. I suspected a format/timezone mismatch that would shift re-seen timestamps in the browser. **Not a bug:** `glebarez/sqlite` returns `CURRENT_TIMESTAMP` as RFC3339 UTC (`2026-09-25T01:31:47Z`), identical in shape and zone to the insert path — only sub-second precision differs, and all timestamp ordering already goes through `julianday(...)` (see [`migrate.go:97`](internal/database/migrate.go#L97), [`subdomains.go:163`](internal/api/subdomains.go#L163)) which is precision-agnostic.
- **Go zero-time rendering in the dashboard.** A never-scanned profile serializes `LastScan` as the truthy string `"0001-01-01T00:00:00Z"`, which naively would render as a year-1 date. **Not a bug:** both date formatters guard it — `overviewUTC` rejects `getUTCFullYear() < 2000` ([`home.html:643`](web/templates/home.html#L643)) and `lastRunText` rejects `getFullYear() < 2000` ([`home.html:1091`](web/templates/home.html#L1091)).

## Appendix B — Notes / non-findings worth awareness

- **Per-row diff cost.** Every `diff*` function issues one `SELECT` + one `INSERT/UPDATE` per finding over the single DB connection (`SetMaxOpenConns(1)`). For a profile with tens of thousands of directory findings this is tens of thousands of serialized round-trips per scan. Functionally correct and acknowledged in-code ([`engine.go:456`](internal/engine/engine.go#L456)); a future efficiency pass could batch these.
- **SSE `discovery_update` kinds render generically.** `persistWAFs`/`persistHosts` broadcast kinds `"wafs"`/`"hosts"` that the badge renders literally ("3 wafs"). Harmless, but there is no findings list for those kinds, so the badge implies a tab that doesn't exist. Cosmetic.
- **Scheduler uses the host's local time** while all storage is UTC. Documented behavior, not a bug — restating so it isn't re-flagged.
