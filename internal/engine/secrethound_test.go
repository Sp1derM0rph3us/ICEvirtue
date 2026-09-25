package engine

import (
	"strings"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

const houndJSON = `[
  {"type":"aws","risk":"high","value":"AKIA-test","source_url":"https://a.example.com/app.js","context":["const key = AKIA-test"],"occurrences":2,"description":"AWS key"},
  {"type":"aws","risk":"high","value":"AKIA-test","source_url":"https://b.example.com/app.js","occurrences":1}
]`

func TestSecretHoundURLListAndFindingMetadata(t *testing.T) {
	profile, bin := newPipelineEnv(t, "passive")
	fakeTool(t, bin, "secrethound", `
test "$1" = -i || exit 10
input=$2
test "$3" = -o || exit 11
output=$4
test "$5" = --silent || exit 12
test "$6" = --no-progress || exit 13
case "$input" in *.urls) ;; *) exit 14;; esac
count=0
while IFS= read -r line; do
  case "$line" in
    https://a.example.com/app.js|https://b.example.com/app.js) count=$((count + 1));;
    *) exit 15;;
  esac
done < "$input"
test "$count" -eq 2 || exit 16
printf '%s\n' '`+houndJSON+`' > "$output"
`)
	findings, err := scanWithSecretHound(profile, []string{
		"https://a.example.com/app.js", "https://a.example.com/app.js",
		"https://b.example.com/app.js", "file:///tmp/app.js", "javascript:bad",
	})
	if err != nil {
		t.Fatalf("scanWithSecretHound: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want two sources", len(findings))
	}
	first := findings[0]
	if first.Engine != "SecretHound" || first.Risk != "high" || first.Description != "AWS key" ||
		first.Occurrences != 2 || len(first.Context) != 1 || first.Context[0] != "const key = AKIA-test" {
		t.Fatalf("lost SecretHound metadata: %+v", first)
	}
	if got := diffSecrets(&profile.ID, findings); got != 2 {
		t.Fatalf("persisted %d new findings, want 2", got)
	}
	if n := countRows(t, &models.SecretFinding{}, profile.ID); n != 2 {
		t.Fatalf("stored %d findings, want 2", n)
	}
	findings[0].Risk = "medium"
	findings[0].Occurrences = 3
	findings[0].Context = []string{"updated context"}
	if got := diffSecrets(&profile.ID, findings); got != 0 {
		t.Fatalf("rescan inserted %d rows, want 0", got)
	}
	var updated models.SecretFinding
	if err := database.DB.Where("source_url = ?", findings[0].SourceURL).First(&updated).Error; err != nil {
		t.Fatal(err)
	}
	if updated.Risk != "medium" || updated.Occurrences != 3 || len(updated.Context) != 1 || updated.Context[0] != "updated context" {
		t.Fatalf("rescan did not update metadata: %+v", updated)
	}
}

func TestSecretHoundOutputFailuresAndPartialResults(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantCount  int
		wantError  bool
	}{
		{"empty", `printf 'null\n' > "$4"`, 0, false},
		{"malformed JSON", `printf '[broken\n' > "$4"`, 0, true},
		{"failed with valid JSON", `printf '%s\n' '` + houndJSON + `' > "$4"; exit 1`, 2, true},
		{"missing output", `exit 1`, 0, true},
		{"malformed finding", `printf '%s\n' '[{"type":"aws","value":"x","source_url":"file:///etc/passwd"}]' > "$4"`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, bin := newPipelineEnv(t, "passive")
			fakeTool(t, bin, "secrethound", tc.body)
			findings, err := scanWithSecretHound(profile, []string{"https://a.example.com/app.js", "https://b.example.com/app.js"})
			if len(findings) != tc.wantCount || (err != nil) != tc.wantError {
				t.Fatalf("got %d findings, error %v; want %d, error=%v", len(findings), err, tc.wantCount, tc.wantError)
			}
		})
	}
}

func TestStageSecretsContinuesWhenSecretHoundFails(t *testing.T) {
	profile, bin := newPipelineEnv(t, "passive")
	fakeTool(t, bin, "waymore", `
while [ "$#" -gt 0 ]; do
  case "$1" in -oU) shift; output=$1;; esac
  shift
done
printf '%s\n' 'https://a.example.com/app.js' > "$output"
`)
	fakeTool(t, bin, "httpx", `printf '%s\n' 'https://a.example.com/app.js'`)
	fakeTool(t, bin, "secrethound", `exit 1`)
	fakeTool(t, bin, "mantra", `
test "$1" = -s || exit 9
IFS= read -r source || exit 10
test "$source" = 'https://a.example.com/app.js' || exit 11
printf '\033[1;32m[+]\033[37m https://a.example.com/app.js \033[1;32m[\033[37mAKIA-test\033[1;32m]\033[37m\n'
`)
	findings, report := stageSecrets(profile, nil)
	if len(findings) != 1 || findings[0].Engine != "Mantra" ||
		findings[0].SourceURL != "https://a.example.com/app.js" || findings[0].SecretType != "generic" {
		t.Fatalf("Mantra finding lost after SecretHound failure: %+v", findings)
	}
	if report.failed() != 1 {
		t.Fatalf("stage reported %d failures, want one", report.failed())
	}
}

func TestMergeSecretsPrefersSourcedResults(t *testing.T) {
	hound := []models.SecretFinding{
		{SourceURL: "https://a.example.com/app.js", SecretType: "aws", SecretValue: "same", Engine: "SecretHound"},
		{SourceURL: "https://b.example.com/app.js", SecretType: "aws", SecretValue: "same", Engine: "SecretHound"},
	}
	mantra := []models.SecretFinding{
		{SourceURL: "https://a.example.com/app.js", SecretType: "generic", SecretValue: "same", Engine: "Mantra"},
		{SourceURL: "https://c.example.com/app.js", SecretType: "generic", SecretValue: "same", Engine: "Mantra"},
		{SourceURL: "https://a.example.com/app.js", SecretType: "generic", SecretValue: "other", Engine: "Mantra"},
	}
	merged := mergeSecrets(hound, mantra)
	if len(merged) != 4 || merged[0].SourceURL == merged[1].SourceURL ||
		merged[2].SourceURL != "https://c.example.com/app.js" || merged[3].SecretValue != "other" {
		t.Fatalf("unexpected merged findings: %+v", merged)
	}
}

func TestMergeSecretsCombinesLiveAndArchivedEvidence(t *testing.T) {
	source := "https://a.example.com/app.js"
	archive := "https://web.archive.org/web/20200101000000/" + source
	hound := []models.SecretFinding{
		{SourceURL: source, SecretType: "aws", SecretValue: "same", Engine: "SecretHound", ArchiveURL: archive},
		{SourceURL: source, SecretType: "aws", SecretValue: "same", Engine: "SecretHound", SeenLive: true},
	}
	mantra := []models.SecretFinding{{SourceURL: source, SecretType: "generic", SecretValue: "same", Engine: "Mantra", SeenLive: true}}
	merged := mergeSecrets(hound, mantra)
	if len(merged) != 1 || !merged[0].SeenLive || merged[0].ArchiveURL != archive || merged[0].Engine != "SecretHound" {
		t.Fatalf("evidence was not merged: %+v", merged)
	}
}

func TestSeparateScansPreserveArchiveEvidenceAcrossScannerTypes(t *testing.T) {
	id := newDiffEnv(t)
	source := "https://a.example.com/app.js"
	archive := "https://web.archive.org/web/20200101000000/" + source
	if got := diffSecrets(&id, []models.SecretFinding{{ProfileID: id, SourceURL: source,
		SecretType: "aws", SecretValue: "same", Engine: "SecretHound", ArchiveURL: archive}}); got != 1 {
		t.Fatalf("initial archive finding count = %d", got)
	}
	if got := diffSecrets(&id, []models.SecretFinding{{ProfileID: id, SourceURL: source,
		SecretType: "generic", SecretValue: "same", Engine: "Mantra", SeenLive: true}}); got != 0 {
		t.Fatalf("later Mantra scan inserted %d duplicate(s)", got)
	}
	var row models.SecretFinding
	if err := database.DB.Where("profile_id = ?", id).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Engine != "SecretHound" || !row.SeenLive || row.ArchiveURL != archive {
		t.Fatalf("lost archive or live evidence: %+v", row)
	}
}

func TestMantraCannotDowngradeSecretHoundRecord(t *testing.T) {
	id := newDiffEnv(t)
	source := "https://a.example.com/app.js"
	hound := models.SecretFinding{
		ProfileID: id, SourceURL: source, SecretType: "generic", SecretValue: "shared",
		Engine: "SecretHound", Risk: "high", Description: "known risk",
		Context: []string{"source context"}, Occurrences: 2,
	}
	if got := diffSecrets(&id, []models.SecretFinding{hound}); got != 1 {
		t.Fatalf("inserted %d SecretHound findings, want 1", got)
	}
	mantra := models.SecretFinding{
		ProfileID: id, SourceURL: source, SecretType: "generic", SecretValue: "shared", Engine: "Mantra",
	}
	if got := diffSecrets(&id, []models.SecretFinding{mantra}); got != 0 {
		t.Fatalf("Mantra rescan inserted %d findings, want 0", got)
	}
	var stored models.SecretFinding
	if err := database.DB.Where("profile_id = ? AND source_url = ?", id, source).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Engine != "SecretHound" || stored.Risk != "high" || stored.Description != "known risk" ||
		stored.Occurrences != 2 || len(stored.Context) != 1 || stored.Context[0] != "source context" {
		t.Fatalf("Mantra replaced SecretHound metadata: %+v", stored)
	}
}

func TestSecretHoundRediscoveryLabelsLegacyRow(t *testing.T) {
	id := newDiffEnv(t)
	legacy := models.SecretFinding{
		ProfileID: id, SourceURL: "https://a.example.com/app.js", SecretType: "aws", SecretValue: "same",
	}
	if err := database.DB.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	rediscovered := legacy
	rediscovered.ID = 0
	rediscovered.Engine = "SecretHound"
	rediscovered.Risk = "high"
	rediscovered.Context = []string{"found again"}
	if got := diffSecrets(&id, []models.SecretFinding{rediscovered}); got != 0 {
		t.Fatalf("rediscovery inserted %d rows, want 0", got)
	}
	var updated models.SecretFinding
	if err := database.DB.First(&updated, legacy.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.Engine != "SecretHound" || updated.Risk != "high" || len(updated.Context) != 1 {
		t.Fatalf("legacy finding was not updated: %+v", updated)
	}
}

func TestSecretHoundRejectsNonHTTPInput(t *testing.T) {
	profile, _ := newPipelineEnv(t, "passive")
	findings, err := scanWithSecretHound(profile, []string{"file:///tmp/a.js", "not a URL"})
	if len(findings) != 0 || err == nil || !strings.Contains(err.Error(), "no valid HTTP") {
		t.Fatalf("got %v, %v; want input validation error", findings, err)
	}
}

func TestSecretHoundToolPathOverride(t *testing.T) {
	resetToolPaths(t)
	bin := t.TempDir()
	path := writeStub(t, bin, "hound-custom", "exit 0")
	ToolPaths = "secrethound=" + path
	got, err := resolveTool("secrethound")
	if err != nil || got != path {
		t.Fatalf("resolveTool(secrethound) = %q, %v; want %q", got, err, path)
	}
}
