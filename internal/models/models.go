package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
)

type User struct {
	ID           uint           `gorm:"primaryKey"`
	Username     string         `gorm:"uniqueIndex:idx_username;not null"`
	PasswordHash string         `gorm:"not null"`
	CreatedAt    time.Time      `gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

type Profile struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	Domain     string    `gorm:"uniqueIndex:idx_domain;not null"`
	Schedule   string
	Mode       string
	Enabled    bool
	IsScanning bool
	LastScan   time.Time
	// LastScanStatus is a short controlled summary of the last run, such as
	// "completed" or "halted: no host answered HTTP". It is rendered in the
	// dashboard, so it must never carry raw tool output.
	LastScanStatus string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`

	Subdomains        []Subdomain
	AliveHosts        []AliveHost
	Vulnerabilities   []Vulnerability
	SecretFindings    []SecretFinding
	DirectoryFindings []DirectoryFinding
}

func (profile *Profile) BeforeCreate(tx *gorm.DB) (err error) {
	if profile.ID == uuid.Nil {
		profile.ID = uuid.New()
	}
	return
}

// Host is derived in a hook rather than at each call site.
//
// The alternative was setting it in the five diff* functions in internal/engine
// plus each of the parsers that build these structs — eleven places that would
// each have to keep remembering, including in code nobody has written yet.
// BeforeSave fires on Create, including slice creates, so forgetting is not
// possible. It follows the convention Profile.BeforeCreate above already sets.
//
// One gap this does NOT cover: hooks do not fire for Model(&row).Update(...),
// which is the "this row already exists" branch of every diff*. Those branches
// write host explicitly, which also repairs any row the backfill could not reach.

func (s *Subdomain) BeforeSave(tx *gorm.DB) error {
	s.Host = hostkey.NormalizeOrNil(s.Domain)
	return nil
}

func (a *AliveHost) BeforeSave(tx *gorm.DB) error {
	a.Host = hostkey.NormalizeOrNil(a.URL)
	return nil
}

// The key comes from URL, which is nuclei's matched-at — the host the finding was
// actually observed on, which may be a redirect target rather than the name that
// was fed in.
func (v *Vulnerability) BeforeSave(tx *gorm.DB) error {
	v.Host = hostkey.NormalizeOrNil(v.URL)
	return nil
}

func (s *SecretFinding) BeforeSave(tx *gorm.DB) error {
	s.Host = hostkey.NormalizeOrNil(s.SourceURL)
	return nil
}

// SubdomainURL, not DirURL: both name the same host, but SubdomainURL is the host
// the fuzzer was pointed at, so it is the more direct statement of intent.
func (d *DirectoryFinding) BeforeSave(tx *gorm.DB) error {
	d.Host = hostkey.NormalizeOrNil(d.SubdomainURL)
	return nil
}

// Host is the key that correlates a finding with the subdomain it was found on.
//
// It is a *string so that "no usable host" is stored as SQL NULL. NULL never
// equals NULL, so a finding whose URL carried no host cannot be joined to
// anything, by any query anyone writes, ever. With "" as the sentinel a single
// forgotten `AND host <> ''` would attribute every such finding to every other
// row that also failed to parse — the failure mode is unrepresentable rather than
// merely documented.
//
// Both sides of the correlation are produced by hostkey.Normalize, and the
// BeforeSave hooks above are what guarantee that. See internal/hostkey.
//
// The new indexes all carry a fresh name: AutoMigrate checks for an index by name
// only, so editing an existing index's definition is silently never applied. They
// are partial on deleted_at IS NULL, which is a syntactic match for the clause
// GORM appends to every soft-deleted model, so SQLite can prove the query implies
// the index predicate. Verified: the planner does choose them, including for
// GORM's table-qualified form of that clause.
//
// host IS NOT NULL is deliberately absent from the predicates — relying on the
// optimizer to infer it from `host = ?` risks the index being silently ignored,
// and the handful of NULL entries cost nothing to skip.

type Subdomain struct {
	ID uint `gorm:"primaryKey"`
	// idx_sub_host is not unique: "A.example.com" and "a.example.com" may already
	// exist as two rows in a live database, and a unique index would fail the
	// migration. Domain is left exactly as discovered — it is the displayed value
	// and it sits inside the unique index — so Host is added alongside it rather
	// than normalizing in place.
	ProfileID uuid.UUID      `gorm:"type:uuid;uniqueIndex:idx_profile_subdomain;index:idx_sub_host,priority:1,where:deleted_at IS NULL;not null"`
	Domain    string         `gorm:"uniqueIndex:idx_profile_subdomain;not null"`
	Host      *string        `gorm:"index:idx_sub_host,priority:2"`
	FirstSeen time.Time      `gorm:"autoCreateTime"`
	LastSeen  time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type AliveHost struct {
	ID uint `gorm:"primaryKey"`
	// status_code rides along in idx_host_status so the representative status for a
	// host is an index-only MIN() rather than a row fetch. IP is deliberately left
	// out: only the node detail header needs it, and that reads at most a row or two.
	ProfileID  uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_profile_host;index:idx_host_status,priority:1,where:deleted_at IS NULL;not null"`
	URL        string    `gorm:"uniqueIndex:idx_profile_host;not null"`
	Host       *string   `gorm:"index:idx_host_status,priority:2"`
	IP         string
	Title      string
	WebServer  string
	StatusCode int            `gorm:"index:idx_host_status,priority:3"`
	FirstSeen  time.Time      `gorm:"autoCreateTime"`
	LastSeen   time.Time      `gorm:"autoUpdateTime"`
	DeletedAt  gorm.DeletedAt `gorm:"index"`
}

type Vulnerability struct {
	ID          uint      `gorm:"primaryKey"`
	ProfileID   uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_profile_vuln;index:idx_vuln_host,priority:1,where:deleted_at IS NULL;not null"`
	TemplateID  string    `gorm:"uniqueIndex:idx_profile_vuln;not null"`
	URL         string    `gorm:"uniqueIndex:idx_profile_vuln;not null"`
	Host        *string   `gorm:"index:idx_vuln_host,priority:2"`
	Severity    string    `gorm:"not null"`
	Name        string
	Description string
	FirstSeen   time.Time      `gorm:"autoCreateTime"`
	LastSeen    time.Time      `gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

type SecretFinding struct {
	ID uint `gorm:"primaryKey"`
	// SourceURL is sometimes the literal placeholder "mantra-discovery" rather than
	// a URL, so Host is NULL for those rows and they are attributed to no node —
	// which is exactly what happened before, since "mantra-discovery".includes(domain)
	// was never true either. Exact-host matching costs those findings nothing.
	ProfileID   uuid.UUID      `gorm:"type:uuid;uniqueIndex:idx_profile_secret;index:idx_secret_host,priority:1,where:deleted_at IS NULL;not null"`
	SourceURL   string         `gorm:"uniqueIndex:idx_profile_secret;not null"`
	Host        *string        `gorm:"index:idx_secret_host,priority:2"`
	SecretType  string         `gorm:"uniqueIndex:idx_profile_secret;not null"`
	SecretValue string         `gorm:"uniqueIndex:idx_profile_secret;not null"`
	FirstSeen   time.Time      `gorm:"autoCreateTime"`
	LastSeen    time.Time      `gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

type DirectoryFinding struct {
	ID uint `gorm:"primaryKey"`
	// The widest of the finding tables — tens of thousands of rows for one profile —
	// so idx_dir_host carries dir_url and status_code as well, making both the
	// per-host COUNT(*) and the node's directory listing index-only.
	ProfileID    uuid.UUID      `gorm:"type:uuid;uniqueIndex:idx_profile_dir;index:idx_dir_host,priority:1,where:deleted_at IS NULL;not null"`
	SubdomainURL string         `gorm:"uniqueIndex:idx_profile_dir;not null"`
	Host         *string        `gorm:"index:idx_dir_host,priority:2"`
	DirURL       string         `gorm:"uniqueIndex:idx_profile_dir;index:idx_dir_host,priority:3;not null"`
	StatusCode   int            `gorm:"index:idx_dir_host,priority:4"`
	FirstSeen    time.Time      `gorm:"autoCreateTime"`
	LastSeen     time.Time      `gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

// SchemaMigration records which one-time data migrations have run.
//
// The marker has to be explicit. "host IS NULL" cannot serve as the flag, because
// after this migration NULL legitimately means "this row has no usable host", so
// it is indistinguishable from "not yet backfilled". See internal/database/migrate.go.
type SchemaMigration struct {
	Version   string    `gorm:"primaryKey"`
	AppliedAt time.Time `gorm:"autoCreateTime"`
}
