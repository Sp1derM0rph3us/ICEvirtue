package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
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
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	Domain    string    `gorm:"uniqueIndex:idx_domain;not null"`
	Schedule   string
	Mode       string
	Enabled    bool
	IsScanning bool
	LastScan   time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Subdomains      []Subdomain
	AliveHosts      []AliveHost
	Vulnerabilities []Vulnerability
	SecretFindings  []SecretFinding
}

func (profile *Profile) BeforeCreate(tx *gorm.DB) (err error) {
	if profile.ID == uuid.Nil {
		profile.ID = uuid.New()
	}
	return
}

type Subdomain struct {
	ID        uint           `gorm:"primaryKey"`
	ProfileID uuid.UUID      `gorm:"type:uuid;uniqueIndex:idx_profile_subdomain;not null"`
	Domain    string         `gorm:"uniqueIndex:idx_profile_subdomain;not null"`
	FirstSeen time.Time      `gorm:"autoCreateTime"`
	LastSeen  time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type AliveHost struct {
	ID        uint      `gorm:"primaryKey"`
	ProfileID uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_profile_host;not null"`
	URL       string    `gorm:"uniqueIndex:idx_profile_host;not null"`
	IP        string
	Title     string
	WebServer string
	FirstSeen time.Time      `gorm:"autoCreateTime"`
	LastSeen  time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type Vulnerability struct {
	ID          uint      `gorm:"primaryKey"`
	ProfileID   uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_profile_vuln;not null"`
	TemplateID  string    `gorm:"uniqueIndex:idx_profile_vuln;not null"`
	URL         string `gorm:"uniqueIndex:idx_profile_vuln;not null"`
	Severity    string `gorm:"not null"`
	Name        string
	Description string
	FirstSeen   time.Time      `gorm:"autoCreateTime"`
	LastSeen    time.Time      `gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

type SecretFinding struct {
	ID          uint           `gorm:"primaryKey"`
	ProfileID   uuid.UUID      `gorm:"type:uuid;uniqueIndex:idx_profile_secret;not null"`
	SourceURL   string         `gorm:"uniqueIndex:idx_profile_secret;not null"`
	SecretType  string         `gorm:"uniqueIndex:idx_profile_secret;not null"`
	SecretValue string         `gorm:"uniqueIndex:idx_profile_secret;not null"`
	FirstSeen   time.Time      `gorm:"autoCreateTime"`
	LastSeen    time.Time      `gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}
