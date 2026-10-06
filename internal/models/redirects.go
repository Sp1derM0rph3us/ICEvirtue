package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

// Redirect observations are findings owned by the original node, not the destination.
type RedirectObservation struct {
	DeletedAt            gorm.DeletedAt `gorm:"index"`
	ID                   uint           `gorm:"primaryKey"`
	ProfileID            uuid.UUID      `gorm:"type:uuid;not null;uniqueIndex:idx_redirect_source;index:idx_redirect_host,priority:1"`
	Host                 string         `gorm:"not null;index:idx_redirect_host,priority:2"`
	SourceURL            string         `gorm:"not null;uniqueIndex:idx_redirect_source"`
	DestinationURL       string
	DestinationHost      string `gorm:"index"`
	Kind                 string `gorm:"index:idx_redirect_host,priority:3"`
	PreviouslyEnumerated bool
	StatusCode           int
	ObservedAt           time.Time
}
