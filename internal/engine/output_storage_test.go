package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestToolOutputLifecycle(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	for _, tc := range []struct {
		name, script string
		timeout      time.Duration
		fail         bool
	}{
		{"success", "printf 'first\\nsecond\\n'", time.Second, false},
		{"failure", "printf 'first\\nsecond\\n'; exit 1", time.Second, true},
		{"timeout", "printf 'first\\nsecond\\n'; /bin/sleep 5", 100 * time.Millisecond, true},
		{"malformed", "printf '{bad json\\n'", time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runTool("sh", []string{"-c", tc.script}, nil, tc.timeout)
			if (err != nil) != tc.fail {
				out.Close()
				t.Fatalf("execution error = %v", err)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				out.Close()
				t.Fatalf("temporary files = %d", len(entries))
			}
			if tc.name == "malformed" {
				if _, err := parseWAFW00FOutput(out); err == nil {
					t.Error("expected parse failure")
				}
			} else if got := readToolOutput(t, out); got != "first\nsecond\n" {
				t.Errorf("partial output = %q", got)
			}
			if err := out.Close(); err != nil {
				t.Fatal(err)
			}
			entries, _ = os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatal("output file leaked")
			}
		})
	}
}

func TestOutputCreationAndWriteFailures(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	out, err := runTool("sh", []string{"-c", "echo ignored"}, nil, time.Second)
	defer out.Close()
	if err == nil || !strings.Contains(err.Error(), "output file") {
		t.Fatalf("creation error = %v", err)
	}
	if got := readToolOutput(t, out); got != "" {
		t.Fatal("expected empty readable output")
	}
	// A closed regular file deterministically simulates a storage write failure.
	file, err := os.CreateTemp(t.TempDir(), "write-failure")
	if err != nil {
		t.Fatal(err)
	}
	output := &toolOutput{File: file}
	if _, err := output.Write([]byte("saved\n")); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := output.Write([]byte("lost")); err == nil || output.writeErr == nil {
		t.Fatal("write failure not retained")
	}
	saved, err := os.ReadFile(file.Name())
	if err != nil || string(saved) != "saved\n" {
		t.Fatalf("preceding bytes lost: %q %v", saved, err)
	}
	if _, err := output.Seek(0, io.SeekStart); err == nil {
		t.Fatal("expected rewind failure on closed file")
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }
func TestOutputReaderErrorPreservesFindings(t *testing.T) {
	boom := errors.New("storage read failed")
	reader := io.MultiReader(strings.NewReader("{\"url\":\"https://example.com\"}\n"), failingReader{boom})
	hosts, err := parseHttpxOutput(reader, uuid.New())
	if len(hosts) != 1 || !errors.Is(err, boom) {
		t.Fatalf("hosts=%v error=%v", hosts, err)
	}
}

// Fixture construction is excluded. Large fields are ignored by the parser,
// so retained findings do not obscure the raw-output allocation comparison.
func BenchmarkOutputParsing(b *testing.B) {
	for _, count := range []int{8, 64} {
		dir := b.TempDir()
		name := filepath.Join(dir, "output.jsonl")
		file, err := os.Create(name)
		if err != nil {
			b.Fatal(err)
		}
		line := `{"url":"https://example.com","unused":"` + strings.Repeat("x", 128*1024) + "\"}\n"
		for i := 0; i < count; i++ {
			if _, err := io.WriteString(file, line); err != nil {
				b.Fatal(err)
			}
		}
		file.Close()
		for _, buffered := range []bool{true, false} {
			label := "file"
			if buffered {
				label = "buffered"
			}
			b.Run(label+"/"+stringSize(count), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(count * len(line)))
				for i := 0; i < b.N; i++ {
					f, err := os.Open(name)
					if err != nil {
						b.Fatal(err)
					}
					var reader io.Reader = f
					if buffered {
						data, err := io.ReadAll(f)
						if err != nil {
							b.Fatal(err)
						}
						reader = bytes.NewBuffer(data)
					}
					var count int
					if buffered {
						data := reader.(*bytes.Buffer)
						scanner := bufio.NewScanner(data)
						scanner.Buffer(make([]byte, 0, 64*1024), max(1024*1024, data.Len()+1))
						seen := map[string]bool{}
						for scanner.Scan() {
							var result HttpxResult
							if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
								b.Fatal(err)
							}
							if !seen[result.URL] {
								seen[result.URL] = true
								count++
							}
						}
						err = scanner.Err()
					} else {
						findings, parseErr := parseHttpxOutput(reader, uuid.Nil)
						count, err = len(findings), parseErr
					}
					f.Close()
					if err != nil || count != 1 {
						b.Fatalf("parse: %v", err)
					}
				}
			})
		}
	}
}
func stringSize(n int) string {
	if n == 8 {
		return "1MiB"
	}
	return "8MiB"
}
