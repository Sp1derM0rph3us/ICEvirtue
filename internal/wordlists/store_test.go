package wordlists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if e := database.InitDatabase(filepath.Join(dir, "test.db")); e != nil {
		t.Fatal(e)
	}
	s, e := New(database.DB, filepath.Join(dir, "uploads"), filepath.Join(dir, "web"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close(); db, _ := s.DB.DB(); db.Close() })
	return s
}
func allowed(*gorm.DB) error { return nil }
func TestContentNamesAndProtectedDeletion(t *testing.T) {
	s := testStore(t)
	body := "# words\r\nadmin\r\nlogin\n"
	item, e := s.Upload(context.Background(), "../../list.txt", "directory", "admin", strings.NewReader(body), allowed)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(hash[:]) + "_directory-wordlist"
	if item.Filename != want || item.Name != "list.txt" || item.Entries != 2 {
		t.Fatalf("wrong metadata %+v", item)
	}
	stored, e := os.ReadFile(filepath.Join(s.Path, want))
	if e != nil || string(stored) != body {
		t.Fatal("stored content differs")
	}
	if _, e = s.Upload(context.Background(), "different.txt", "directory", "admin", strings.NewReader(body), allowed); !errors.Is(e, ErrDuplicate) {
		t.Fatalf("duplicate %v", e)
	}
	c, _ := appconfig.Load(s.DB)
	c.Scan.DirectoryWordlists = []string{item.ID}
	s.DB.Save(&c)
	if e = s.Delete(item.ID, allowed); !errors.Is(e, ErrInUse) {
		t.Fatal(e)
	}
	c.Scan.DirectoryWordlists = []string{}
	s.DB.Save(&c)
	s.DB.Create(&models.WordlistPin{JobID: 1, WordlistID: item.ID})
	if e = s.Delete(item.ID, allowed); !errors.Is(e, ErrInUse) {
		t.Fatal(e)
	}
	s.DB.Delete(&models.WordlistPin{}, "job_id = ?", 1)
	if e = s.Delete(item.ID, allowed); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(s.Path, want)); !os.IsNotExist(e) {
		t.Fatal("file not deleted")
	}
}
func TestInvalidUploadsLeaveNoFilesOrQuota(t *testing.T) {
	s := testStore(t)
	for _, body := range []string{"", "# comment\n \n", "abc\x00def\n", "abc\xff\n", strings.Repeat("a", 4097) + "\n"} {
		if _, e := s.Upload(context.Background(), "list.txt", "subdomain", "admin", strings.NewReader(body), allowed); e == nil {
			t.Fatal("invalid content accepted")
		}
	}
	calls := 0
	_, e := s.Upload(context.Background(), "list.txt", "subdomain", "admin", strings.NewReader("www\n"), func(*gorm.DB) error {
		calls++
		if calls == 2 {
			return errors.New("session revoked")
		}
		return nil
	})
	if e == nil {
		t.Fatal("revoked upload committed")
	}
	var count int64
	s.DB.Model(&models.Wordlist{}).Count(&count)
	files, _ := os.ReadDir(s.Path)
	if count != 0 || len(files) != 0 {
		t.Fatalf("failed upload leaked: rows %d files %d", count, len(files))
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("disconnected") }
func TestInterruptedAndQuotaUploads(t *testing.T) {
	s := testStore(t)
	if _, e := s.Upload(context.Background(), "list.txt", "directory", "admin", io.MultiReader(strings.NewReader("admin\n"), failReader{}), allowed); e == nil {
		t.Fatal("interrupted upload accepted")
	}
	s.DB.Create(&models.Wordlist{ID: "reserved", State: "ready", Bytes: MaxTotalBytes})
	if _, e := s.Upload(context.Background(), "list.txt", "directory", "admin", strings.NewReader("admin\n"), allowed); !errors.Is(e, ErrQuota) {
		t.Fatalf("quota not enforced: %v", e)
	}
}
func TestRecoveryAndSymlinkIsolation(t *testing.T) {
	s := testStore(t)
	id := "00000000-0000-0000-0000-000000000001"
	part := id + ".part"
	s.DB.Create(&models.Wordlist{ID: id, Filename: part, State: "staging", Bytes: MaxFileBytes})
	os.WriteFile(filepath.Join(s.Path, part), []byte("partial"), 0600)
	if e := s.Reconcile(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(s.Path, part)); !os.IsNotExist(e) {
		t.Fatal("staged file survived")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("do not touch"), 0600)
	sum := strings.Repeat("a", 64)
	name := Filename(sum, "directory")
	os.Symlink(outside, filepath.Join(s.Path, name))
	s.DB.Create(&models.Wordlist{ID: "unsafe", Filename: name, SHA256: sum, Kind: "directory", State: "ready"})
	if e := s.Reconcile(); e == nil {
		t.Fatal("ready symlink accepted")
	}
	body, _ := os.ReadFile(outside)
	if string(body) != "do not touch" {
		t.Fatal("escaped upload root")
	}
	if _, e := New(s.DB, filepath.Join(s.Path, "public"), s.Path); e == nil {
		t.Fatal("public storage overlap accepted")
	}
}

type generatedWords struct {
	remaining   int64
	largestRead int
}

func (g *generatedWords) Read(p []byte) (int, error) {
	if g.remaining == 0 {
		return 0, io.EOF
	}
	if len(p) > g.largestRead {
		g.largestRead = len(p)
	}
	n := len(p)
	if int64(n) > g.remaining {
		n = int(g.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = "admin\n"[i%6]
	}
	g.remaining -= int64(n)
	return n, nil
}
func TestLargeUploadStreamsThroughBoundedBuffers(t *testing.T) {
	s := testStore(t) // Deliberately generated, never materialized as a large string.
	reader := &generatedWords{remaining: 16 << 20}
	item, e := s.Upload(context.Background(), "large.txt", "directory", "admin", reader, allowed)
	if e != nil {
		t.Fatal(e)
	}
	if item.Bytes != 16<<20 || reader.largestRead > 64<<10 {
		t.Fatalf("upload not streamed: bytes %d read buffer %d", item.Bytes, reader.largestRead)
	}
}
