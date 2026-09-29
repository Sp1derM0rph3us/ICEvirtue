// Package wordlists stores immutable text uploads outside the served filesystem.
package wordlists

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const MaxFileBytes int64 = 1 << 30
const MaxTotalBytes int64 = 10 << 30
const MaxFiles = 50

var ErrBusy = errors.New("another upload is in progress")
var ErrQuota = errors.New("wordlist storage quota exceeded")
var ErrInUse = errors.New("wordlist is selected or used by a running scan")
var ErrDuplicate = errors.New("this wordlist content and type are already stored")

type Authorize func(*gorm.DB) error
type Store struct {
	DB     *gorm.DB
	Root   *os.Root
	Path   string
	upload chan struct{}
	mu     sync.Mutex
}

func overlaps(a, b string) bool {
	rel, e := filepath.Rel(a, b)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
func New(db *gorm.DB, dir, web string) (*Store, error) {
	dir, e := filepath.Abs(dir)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		return nil, e
	}
	web, e = filepath.Abs(web)
	if e != nil {
		return nil, e
	}
	if resolved, err := filepath.EvalSymlinks(web); err == nil {
		web = resolved
	}
	if overlaps(dir, web) || overlaps(web, dir) {
		return nil, errors.New("upload storage must be separate from the web directory")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	return &Store{DB: db, Root: root, Path: dir, upload: make(chan struct{}, 1)}, nil
}
func (s *Store) Close() error          { return s.Root.Close() }
func Filename(sum, kind string) string { return sum + "_" + kind + "-wordlist" }
func (s *Store) Upload(ctx context.Context, name, kind, actor string, body io.Reader, authorize Authorize) (result models.Wordlist, err error) {
	select {
	case s.upload <- struct{}{}:
		defer func() { <-s.upload }()
	default:
		return result, ErrBusy
	}
	if kind != "subdomain" && kind != "directory" {
		return result, appconfig.ValidationError("wordlist kind must be subdomain or directory")
	}
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	ext := strings.ToLower(filepath.Ext(name))
	if !utf8.ValidString(name) || len(name) > 255 || strings.ContainsAny(name, "\x00\r\n") || (ext != ".txt" && ext != ".lst" && ext != ".wordlist") {
		return result, appconfig.ValidationError("upload a .txt, .lst or .wordlist UTF-8 text file")
	}
	var disk syscall.Statfs_t
	if e := syscall.Statfs(s.Path, &disk); e != nil {
		return result, e
	}
	if disk.Bavail*uint64(disk.Bsize) < uint64(MaxFileBytes) {
		return result, ErrQuota
	}
	result = models.Wordlist{ID: uuid.NewString(), Name: name, Kind: kind, State: "staging", Bytes: MaxFileBytes, CreatedBy: actor}
	result.Filename = result.ID + ".part"
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if e := authorize(tx); e != nil {
			return e
		}
		var staged int64
		if e := tx.Model(&models.Wordlist{}).Where("state = ?", "staging").Count(&staged).Error; e != nil {
			return e
		}
		if staged > 0 {
			return ErrBusy
		}
		var usage struct {
			Bytes int64
			Count int64
		}
		if e := tx.Model(&models.Wordlist{}).Select("COALESCE(SUM(bytes),0) AS bytes, COUNT(*) AS count").Scan(&usage).Error; e != nil {
			return e
		}
		if usage.Count >= MaxFiles || usage.Bytes+MaxFileBytes > MaxTotalBytes {
			return ErrQuota
		}
		return tx.Create(&result).Error
	})
	if err != nil {
		return result, err
	}
	temp := result.Filename
	// Failed uploads retain quota if physical cleanup fails, for startup reconciliation.
	defer func() {
		if err != nil {
			if e := s.Root.Remove(temp); e == nil || errors.Is(e, os.ErrNotExist) {
				s.DB.Delete(&models.Wordlist{}, "id = ?", result.ID)
			}
		}
	}()
	f, e := s.Root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return result, e
	}
	hash := sha256.New()
	counter := &countReader{r: io.LimitReader(body, MaxFileBytes+1), ctx: ctx}
	scanner := bufio.NewScanner(io.TeeReader(counter, io.MultiWriter(f, hash)))
	scanner.Buffer(make([]byte, 4096), 4098)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) > 4096 || !utf8.Valid(line) || strings.IndexByte(string(line), 0) >= 0 {
			f.Close()
			return result, appconfig.ValidationError("wordlists require UTF-8 text, no NUL bytes, and lines of at most 4096 bytes")
		}
		word := strings.TrimSpace(string(line))
		if word != "" && !strings.HasPrefix(word, "#") {
			result.Entries++
		}
	}
	scanErr := scanner.Err()
	syncErr := f.Sync()
	closeErr := f.Close()
	if counter.n > MaxFileBytes {
		return result, ErrQuota
	}
	if scanErr != nil {
		return result, appconfig.ValidationError("upload interrupted, invalid text, or line exceeds 4096 bytes")
	}
	if e = errors.Join(syncErr, closeErr, ctx.Err()); e != nil {
		return result, e
	}
	if result.Entries == 0 {
		return result, appconfig.ValidationError("wordlist contains no entries")
	}
	result.Bytes = counter.n
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	final := Filename(result.SHA256, kind)
	// The upload semaphore serializes content-addressed installation. Never replace a ready file.
	if _, e = s.Root.Lstat(final); e == nil {
		return result, ErrDuplicate
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	// Record the intended final path before rename so crash recovery can find either file.
	if e = s.DB.Model(&models.Wordlist{}).Where("id = ?", result.ID).Update("filename", final).Error; e != nil {
		return result, e
	}
	if e = s.Root.Rename(temp, final); e != nil {
		return result, e
	}
	temp = final
	result.Filename = final
	result.State = "ready"
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if e := authorize(tx); e != nil {
			return e
		}
		return tx.Save(&result).Error
	})
	return result, err
}

type countReader struct {
	r   io.Reader
	ctx context.Context
	n   int64
}

func (c *countReader) Read(b []byte) (int, error) {
	if e := c.ctx.Err(); e != nil {
		return 0, e
	}
	n, e := c.r.Read(b)
	c.n += int64(n)
	return n, e
}
func (s *Store) Delete(id string, authorize Authorize) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var item models.Wordlist
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if e := authorize(tx); e != nil {
			return e
		}
		if e := tx.First(&item, "id = ?", id).Error; e != nil {
			return e
		}
		if item.State == "staging" {
			return ErrBusy
		}
		c, e := appconfig.Load(tx)
		if e != nil {
			return e
		}
		for _, v := range append(c.Scan.DNSXWordlists, c.Scan.DirectoryWordlists...) {
			if v == id {
				return ErrInUse
			}
		}
		var n int64
		if e := tx.Model(&models.WordlistPin{}).Where("wordlist_id = ?", id).Count(&n).Error; e != nil {
			return e
		}
		if n > 0 {
			return ErrInUse
		}
		return tx.Model(&item).Update("state", "deleting").Error
	})
	if err != nil {
		return err
	}
	if err = s.Root.Remove(item.Filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.DB.Delete(&item).Error
}

var ownedName = regexp.MustCompile(`^(?:[a-f0-9]{64}_(?:directory|subdomain)-wordlist|[a-f0-9-]{36}\.part)$`)

// Reconcile runs before accepting uploads or starting workers.
func (s *Store) Reconcile() error {
	var items []models.Wordlist
	if err := s.DB.Find(&items).Error; err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, item := range items {
		if item.State == "ready" {
			if !ownedName.MatchString(item.Filename) || item.Filename != Filename(item.SHA256, item.Kind) {
				return errors.New("invalid ready wordlist name")
			}
			info, e := s.Root.Lstat(item.Filename)
			if e != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("ready wordlist %s is missing or not a regular file", item.ID)
			}
			keep[item.Filename] = true
			continue
		}
		for _, name := range []string{item.Filename, item.ID + ".part"} {
			if !ownedName.MatchString(name) {
				return errors.New("invalid stored wordlist filename")
			}
			if e := s.Root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
		if e := s.DB.Delete(&item).Error; e != nil {
			return e
		}
	}
	f, e := s.Root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	entries, e := f.ReadDir(-1)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if ownedName.MatchString(entry.Name()) && !keep[entry.Name()] {
			if e := s.Root.Remove(entry.Name()); e != nil {
				return e
			}
		}
	}
	return nil
}
