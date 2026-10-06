# Directory discovery validation

Directory discovery records three separate facts: the node's numeric root HTTP status, each candidate path's assessment, and any redirect to a different hostname. Calibration never changes the root status. No authenticated requests or cross-host traversal are performed.

## Assessments and filters

- **Confirmed**: differs from an established nonexistent-path baseline and remained consistent on a repeat request.
- **Unknown**: matches missing-path behavior, cannot be compared reliably, exceeds inspection limits, or redirects beyond the permitted boundary. Unknown does not assert that the resource exists or is absent. The observed initial HTTP code and controlled reason are shown beside the label.
- **Legacy**: recorded before this validation update. Existing observations are retained; future scans can assess them.

The node's directory menu defaults to **All** and offers Confirmed and Unknown filters. Legacy rows appear in All. The main Findings view offers an **Unknown directories** filter and separate counts for confirmed, Unknown, and legacy observations. Unknown paths do not increase confirmed scan-finding counts or confirmed finding-volume ranking. Unknown rows can still be numerous because every ambiguous wordlist candidate is retained for review. There is no automatic deletion of older findings.

## Baselines and limits

Three random controls match each candidate's origin, parent directory, extension, trailing slash, and query context. Origins include scheme, normalized hostname, and effective port; baselines are never reused between origins, profiles, or scans. Controls retain unrelated query parameters.

Calibration, candidate requests, redirect hops, and confirmation requests all use the existing 50-worker directory pool. At most 50 requests execute concurrently per scan. The global scan concurrency setting still determines how many such scans can execute. Calibration adds traffic and elapsed time; it does not create another pool. The cache retains at most 100 unused contexts plus at most 50 active contexts. Concurrent users share calibration. Only unused entries are evicted, and a miss recalibrates rather than accepting an unvalidated result.

Responses are compared using the redirect chain, terminal status, content type, and a normalized body fingerprint. Requested paths and URLs, including encoded reflections, and whitespace are normalized. Unrelated redirect parameters are retained. Exact hashes match first. Text containing at least 20 tokens may also match with five-token shingle similarity of at least 95% and normalized lengths within 10%. Short and binary bodies require exact matches. Two controls must agree before a pattern is used.

Each observation has a ten-second deadline across its entire redirect chain and a 256 KiB decoded-body limit. The existing configured directory-stage deadline remains in force. Bodies are not persisted. Committed batches remain if a scan is interrupted. Calibration or transport failures are reported as incomplete validation in run history; blanket responses matching a stable baseline are a normal Unknown outcome.

## Redirect observations

The scanner follows 301, 302, 303, 307, and 308 responses for at most five hops on the original hostname, allowing its original port and standard HTTP/HTTPS ports. HTTP-to-HTTPS upgrades are allowed; HTTPS downgrades, credentials in locations, malformed locations, loops, and disallowed ports are not followed.

At the first different hostname, the scanner records the destination and stops:

- **Cross-Host Redirect**: destination equals the configured profile domain or ends in its dot-delimited subdomain suffix.
- **Cross-Scope Redirect**: destination lies outside that boundary, including sibling domains outside a narrower profile.

Exact membership in the scan's enumeration snapshot determines the separate previously-enumerated annotation. A previously unseen subdomain can still be Cross-Host. Root redirects are inspected during HTTP validation even when directory discovery is disabled. Known destinations are scanned independently under their own baselines if they qualify as targets.

Node badges expose destination summaries through hover, focus, and click/tap. Redirect details provide paginated source URLs, destination URLs, observed initial codes, enumeration annotations, and observation times. Observations belong to the source node. Repeated observations update the same source-URL record; a record is not automatically removed when a later scan omits that URL. The timestamp describes when it was last observed.

## API and deployment

Existing directory responses retain numeric `StatusCode`, with additive `Assessment` and `AssessmentReason` fields. `GET /api/profiles/{id}/directories` accepts `assessment=all|confirmed|unknown`, echoed in page metadata. Node-list responses add `confirmed_dir_count`, `unknown_dir_count`, `legacy_dir_count`, `cross_host_count`, and `cross_scope_count`; existing `dir_count` remains the total observation count. The node filter is `filter=unknown-directories`.

`GET /api/profiles/{id}/redirects?host=...` returns paginated observations. `GET /api/profiles/{id}/redirects/summary?host=...&kind=cross_host|cross_scope` returns up to six destination groups; the compact tooltip displays five and directs operators to details. Both endpoints require an explicit host and remain scoped to the specified profile and existing authorization policies.

Stop workers, back up SQLite and uploads together, and deploy the server, workers, and web assets together. Start the server first to migrate to `2026_10_directory_validation_v1`; updated workers refuse an older schema. The migration adds assessments with legacy defaults and redirect storage without clearing existing findings, current job ownership, or wordlist pins. Start updated workers afterward. Rollback requires restoring the paired pre-upgrade backup and previous binaries/assets.

Run `go test ./...` and the Chromium Playwright suite against disposable fixtures. The validation tests use fake transports and local HTTP servers; they do not scan external applications.
