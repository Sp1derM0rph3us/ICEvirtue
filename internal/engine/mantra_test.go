package engine

import (
	"strings"
	"testing"
)

func TestMantraUsesSupportedCLIAndParsesSourcedFindings(t *testing.T) {
	profile, bin := newPipelineEnv(t, "passive")
	fakeTool(t, bin, "mantra", `
test "$1" = -s || exit 9
IFS= read -r first || exit 10
IFS= read -r second || exit 11
test "$first" = 'https://a.example.com/app.js' || exit 12
test "$second" = 'https://b.example.com/app.js' || exit 13
printf '\033[1;32m[+]\033[37m https://a.example.com/app.js \033[1;32m[\033[37mAKIA-test\033[1;32m]\033[37m\n'
printf '%s\n' '[+] https://b.example.com/app.js [value with [brackets]]'
`)
	findings, err := scanWithMantra(profile, []string{
		"https://a.example.com/app.js", "https://b.example.com/app.js",
		"https://a.example.com/app.js", "file:///tmp/bad.js",
	})
	if err != nil || len(findings) != 2 {
		t.Fatalf("Mantra findings = %+v, error = %v; want two findings", findings, err)
	}
	if findings[0].SourceURL != "https://a.example.com/app.js" || findings[0].SecretValue != "AKIA-test" ||
		findings[1].SourceURL != "https://b.example.com/app.js" || findings[1].SecretValue != "value with [brackets]" {
		t.Fatalf("incorrect Mantra values or sources: %+v", findings)
	}
	for _, finding := range findings {
		if finding.SecretType != "generic" || finding.Engine != "Mantra" || finding.ProfileID != profile.ID {
			t.Errorf("incorrect Mantra metadata: %+v", finding)
		}
	}
}

func TestMantraPreservesPartialOutputAndReportsBadLines(t *testing.T) {
	profile, bin := newPipelineEnv(t, "passive")
	fakeTool(t, bin, "mantra", `
test "$1" = -s || exit 9
printf '%s\n' '[+] https://a.example.com/app.js [first]'
printf '%s\n' '[+] https://a.example.com/app.js []'
printf '%s\n' '[+] https://outside.example.com/app.js [foreign]'
printf '%s\n' 'unexpected output'
printf '%s\n' '[-] Unable to make a request for https://b.example.com/app.js'
exit 1
`)
	findings, err := scanWithMantra(profile, []string{
		"https://a.example.com/app.js", "https://b.example.com/app.js",
	})
	if len(findings) != 1 || findings[0].SecretValue != "first" {
		t.Fatalf("partial Mantra findings = %+v, want one valid result", findings)
	}
	if err == nil || !strings.Contains(err.Error(), "3 malformed output line(s)") ||
		!strings.Contains(err.Error(), "1 request error(s)") || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("Mantra error = %v, want run, parse, and request failures", err)
	}
}

func TestMantraRejectsNonHTTPInput(t *testing.T) {
	profile, _ := newPipelineEnv(t, "passive")
	findings, err := scanWithMantra(profile, []string{"file:///tmp/a.js", "not a URL"})
	if len(findings) != 0 || err == nil || !strings.Contains(err.Error(), "no valid HTTP") {
		t.Fatalf("got %v, %v; want input validation error", findings, err)
	}
}
