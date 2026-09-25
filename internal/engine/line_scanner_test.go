package engine

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestLineScannerLargeLines(t *testing.T) {
	large := strings.Repeat("x", 1024*1024+100)
	for _, tc := range []struct {
		name  string
		input io.Reader
		want  []string
	}{
		{"middle", bytes.NewBufferString("before\n" + large + "\nafter\n"), []string{"before", large, "after"}},
		{"unterminated", bytes.NewBufferString(large), []string{large}},
		{"crlf", bytes.NewBufferString("before\r\n" + large + "\r\nafter\r\n"), []string{"before", large, "after"}},
		{"empty", &bytes.Buffer{}, nil},
		{"nil", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := newLineScanner(tc.input)
			var got []string
			for scanner.Scan() {
				got = append(got, scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("lines differ: got %d, want %d", len(got), len(tc.want))
			}
		})
	}
}

func TestJSONParsersContinueAfterLargeRecords(t *testing.T) {
	large := strings.Repeat("x", 1024*1024+100)
	quoted, err := json.Marshal(large)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []bool{false, true} {
		name := "valid"
		if malformed {
			name = "malformed"
		}
		t.Run(name, func(t *testing.T) {
			first := `{"url":"https://large.example.com","title":` + string(quoted) + `}`
			if malformed {
				first = "{" + large
			}
			hosts, parseErr := parseHttpxOutput(bytes.NewBufferString(first+"\n"+`{"url":"https://after.example.com","title":"after"}`), uuid.New())
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			want := 2
			if malformed {
				want = 1
			}
			if len(hosts) != want {
				t.Fatalf("httpx hosts = %d, want %d", len(hosts), want)
			}
			if hosts[want-1].URL != "https://after.example.com" {
				t.Fatal("httpx lost following record")
			}
			if !malformed && hosts[0].Title != large {
				t.Fatal("httpx truncated large title")
			}

			first = `{"template-id":"large","matched-at":"https://large.example.com","info":{"description":` + string(quoted) + `}}`
			if malformed {
				first = "{" + large
			}
			vulns, parseErr := parseNucleiOutput(bytes.NewBufferString(first+"\n"+`{"template-id":"after","matched-at":"https://after.example.com"}`), uuid.New())
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if len(vulns) != want {
				t.Fatalf("nuclei findings = %d, want %d", len(vulns), want)
			}
			if vulns[want-1].TemplateID != "after" {
				t.Fatal("nuclei lost following record")
			}
			if !malformed && vulns[0].Description != large {
				t.Fatal("nuclei truncated large description")
			}
		})
	}
}
