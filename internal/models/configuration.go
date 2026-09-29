package models

import "time"

type PasswordPolicy struct {
	Minimum int `json:"minimum"`
	Maximum int `json:"maximum"`
}
type ScanSettings struct {
	SkipNuclei         bool     `json:"skip_nuclei"`
	SkipAmass          bool     `json:"skip_amass"`
	SkipDNSX           bool     `json:"skip_dnsx"`
	SkipWAF            bool     `json:"skip_waf"`
	SkipDirectory      bool     `json:"skip_directory"`
	SkipSecrets        bool     `json:"skip_secrets"`
	Verbose            bool     `json:"verbose"`
	WideTargets        bool     `json:"wide_targets"`
	DNSXWordlists      []string `json:"dnsx_wordlists" gorm:"serializer:json"`
	DirectoryWordlists []string `json:"directory_wordlists" gorm:"serializer:json"`
}
type ToolSettings struct {
	WAFTimeoutSeconds    int `json:"waf_timeout_seconds"`
	WaymoreResponseLimit int `json:"waymore_response_limit"`
	MaxConcurrentScans   int `json:"max_concurrent_scans"`
}
type ApplicationConfiguration struct {
	ID        uint           `gorm:"primaryKey;check:id = 1" json:"-"`
	Revision  uint64         `json:"revision"`
	Password  PasswordPolicy `gorm:"embedded;embeddedPrefix:password_" json:"password_policy"`
	Scan      ScanSettings   `gorm:"embedded;embeddedPrefix:scan_" json:"scan"`
	Tools     ToolSettings   `gorm:"embedded;embeddedPrefix:tools_" json:"tools"`
	UpdatedBy string         `json:"updated_by"`
	UpdatedAt time.Time      `json:"updated_at"`
}
type Wordlist struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Filename  string    `json:"-"`
	SHA256    string    `json:"sha256"`
	Bytes     int64     `json:"bytes"`
	Entries   int64     `json:"entries"`
	State     string    `gorm:"index" json:"state"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Only active jobs are retained; the unique profile key arbitrates admission.
type ScanJob struct {
	ID        uint   `gorm:"primaryKey"`
	ProfileID string `gorm:"uniqueIndex;not null"`
	Source    string
	State     string `gorm:"index"`
	Revision  uint64
	CreatedAt time.Time
}
type WordlistPin struct {
	JobID      uint   `gorm:"primaryKey"`
	WordlistID string `gorm:"primaryKey;index"`
}
