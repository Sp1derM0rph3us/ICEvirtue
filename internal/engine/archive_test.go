package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWaymoreCollectsPartialOutputAndMapsCaptures(t *testing.T) {
	profile, bin := newPipelineEnv(t, "passive")
	oldLimit := WaymoreResponseLimit
	WaymoreResponseLimit = 17
	t.Cleanup(func() { WaymoreResponseLimit = oldLimit })
	fakeTool(t, bin, "waymore", `
test "$1" = -i && test "$2" = example.com || exit 10
test "$3" = -mode && test "$4" = B || exit 11
while [ "$#" -gt 0 ]; do
  case "$1" in
    -oU) shift; urls=$1;;
    -oR) shift; responses=$1;;
    -ci) shift; test "$1" = d || exit 12;;
    -l) shift; test "$1" = 17 || exit 13;;
    -c) shift; config=$1;;
  esac
  shift
done
test -f "$config" || exit 14
printf '%s\n' 'https://a.example.com/app.js?x=1' 'https://outside.example.org/app.js' 'https://a.example.com/logo.png' > "$urls"
printf '%s\n' 'secret-one' > "$responses/123.js"
printf '%s\n' 'secret-two' > "$responses/456.json"
printf '%s\n' 'secret-three' > "$responses/789.ts"
printf '%s\n' '123,https://web.archive.org/web/20200101000000/https://a.example.com/app.js?x=1 ,2026-01-01 00:00:00' \
  '123,https://web.archive.org/web/20200102000000/https://a.example.com/app.js?x=1 ,2026-01-01 00:00:00' \
  '123,https://web.archive.org/web/20200103000000/https://b.example.com/app.js ,2026-01-01 00:00:00' \
  '456,https://urlscan.io/dom/abc-123/https://a.example.com/data.json ,2026-01-01 00:00:00' \
  '789,https://ghostarchive.org/archive/abc#https://a.example.com/old.ts ,2026-01-01 00:00:00' \
  '789,https://ghostarchive.org/archive/abc#https://outside.example.org/old.ts ,2026-01-01 00:00:00' \
  'bad record' > "$responses/waymore_index.txt"
exit 1
`)
	urls, refs, cleanup, err := collectWaymore(profile)
	defer cleanup()
	if err == nil || !strings.Contains(err.Error(), "invalid or unmappable") || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("partial Waymore error = %v", err)
	}
	if len(urls) != 1 || urls[0] != "https://a.example.com/app.js?x=1" {
		t.Fatalf("discovered URLs = %v", urls)
	}
	if len(refs) != 3 {
		t.Fatalf("archived files = %v", refs)
	}
	for path, evidence := range refs {
		switch filepath.Base(path) {
		case "123.js":
			if len(evidence) != 2 || evidence[0].OriginalURL != "https://a.example.com/app.js?x=1" || evidence[1].OriginalURL != "https://b.example.com/app.js" {
				t.Fatalf("Wayback dedup mapping = %+v", evidence)
			}
		case "456.json":
			if len(evidence) != 1 || evidence[0].OriginalURL != "https://a.example.com/data.json" || evidence[0].ArchiveURL != "https://urlscan.io/dom/abc-123/" {
				t.Fatalf("URLScan mapping = %+v", evidence)
			}
		case "789.ts":
			if len(evidence) != 1 || evidence[0].OriginalURL != "https://a.example.com/old.ts" || evidence[0].ArchiveURL != "https://ghostarchive.org/archive/abc" {
				t.Fatalf("GhostArchive mapping = %+v", evidence)
			}
		default:
			t.Fatalf("unexpected archived path %s", path)
		}
	}
}

func TestSecretHoundScansLiveAndArchiveInOneRun(t *testing.T) {
	profile, bin := newPipelineEnv(t, "passive")
	archivedPath := filepath.Join(t.TempDir(), "123.js")
	if err := os.WriteFile(archivedPath, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	fakeTool(t, bin, "secrethound", `
test "$1" = -i && test "$3" = -o || exit 10
input=$2
output=$4
count=0
while IFS= read -r line; do
  count=$((count + 1))
  case "$line" in
    https://a.example.com/app.js) live=$line;;
    */123.js) local=$line;;
    *) exit 11;;
  esac
done < "$input"
test "$count" -eq 2 && test -f "$local" || exit 12
printf '[{"type":"aws","value":"live","source_url":"%s"},{"type":"aws","value":"old","source_url":"file://%s"}]\n' "$live" "$local" > "$output"
`)
	refs := map[string][]archiveEvidence{archivedPath: {
		{OriginalURL: "https://a.example.com/old.js", ArchiveURL: "https://web.archive.org/web/20200101000000/https://a.example.com/old.js"},
	}}
	findings, err := scanWithSecretHoundSources(profile, []string{"https://a.example.com/app.js"}, refs)
	if err != nil || len(findings) != 2 {
		t.Fatalf("mixed SecretHound findings = %+v, error = %v", findings, err)
	}
	if !findings[0].SeenLive || findings[0].ArchiveURL != "" || findings[1].SeenLive || findings[1].SourceURL != "https://a.example.com/old.js" || findings[1].ArchiveURL == "" {
		t.Fatalf("wrong evidence mapping: %+v", findings)
	}
}

func TestStageSecretsScansArchiveWithoutLiveURLs(t *testing.T) {
	profile, bin := newPipelineEnv(t, "passive")
	fakeTool(t, bin, "waymore", `
while [ "$#" -gt 0 ]; do
  case "$1" in
    -oR) shift; responses=$1;;
  esac
  shift
done
printf '%s\n' 'archived secret' > "$responses/123.js"
printf '%s\n' '123,https://web.archive.org/web/20200101000000/https://a.example.com/old.js ,2026-01-01 00:00:00' > "$responses/waymore_index.txt"
`)
	fakeTool(t, bin, "secrethound", `
test "$1" = -i && test "$3" = -o || exit 10
IFS= read -r local < "$2"
case "$local" in */123.js) ;; *) exit 11;; esac
printf '[{"type":"aws","value":"old","source_url":"file://%s"}]\n' "$local" > "$4"
`)
	findings, report := stageSecrets(profile, nil)
	if report.failed() != 0 || len(findings) != 1 {
		t.Fatalf("archive-only scan: %+v, report: %+v", findings, report)
	}
	finding := findings[0]
	if finding.SourceURL != "https://a.example.com/old.js" || finding.ArchiveURL == "" || finding.SeenLive || finding.Engine != "SecretHound" {
		t.Fatalf("archive-only finding: %+v", finding)
	}
}

func TestWaymoreResponseWithoutIndexIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "123.js"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := readWaymoreIndex(dir, "example.com")
	if len(findings) != 0 || err == nil || !strings.Contains(err.Error(), "without a capture index") {
		t.Fatalf("missing capture index: %+v, %v", findings, err)
	}
}
