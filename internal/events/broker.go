// Package events is the durable cross-process dashboard event stream.
package events

import (
	"encoding/json"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
	"time"
)

const MaxRows = 100000

type Event struct {
	ID        uint64          `json:"id"`
	Type      string          `json:"type"`
	ProfileID string          `json:"profile_id"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// Append must receive the transaction which committed the corresponding change.
func Append(tx *gorm.DB, kind, profile string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if e := tx.Create(&models.OutboxEvent{Type: kind, ProfileID: profile, Data: string(b)}).Error; e != nil {
		return e
	}
	return tx.Where("id <= (SELECT MAX(id) - ? FROM outbox_events)", MaxRows).Delete(&models.OutboxEvent{}).Error
}

type Stream struct{ DB *gorm.DB }

func (s *Stream) Bounds() (first, last uint64, err error) {
	var row struct{ First, Last uint64 }
	err = s.DB.Model(&models.OutboxEvent{}).Select("COALESCE(MIN(id),0) AS first, COALESCE(MAX(id),0) AS last").Where("created_at >= ?", time.Now().UTC().Add(-24*time.Hour)).Scan(&row).Error
	return row.First, row.Last, err
}
func (s *Stream) Read(after uint64) ([]Event, error) {
	var rows []models.OutboxEvent
	err := s.DB.Where("id > ? AND created_at >= ?", after, time.Now().UTC().Add(-24*time.Hour)).Order("id").Limit(100).Find(&rows).Error
	out := make([]Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, Event{r.ID, r.Type, r.ProfileID, json.RawMessage(r.Data)})
	}
	return out, err
}
