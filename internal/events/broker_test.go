package events

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
	"path/filepath"
	"testing"
	"time"
)

func TestOutboxCapAndReplayWindow(t *testing.T) {
	s, e := database.Open(filepath.Join(t.TempDir(), "events.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.DB.Create(&models.OutboxEvent{ID: 1, Type: "old", Data: "null"})
	s.DB.Create(&models.OutboxEvent{ID: MaxRows + 1, Type: "recent", Data: "null"})
	if e = s.DB.Transaction(func(tx *gorm.DB) error { return Append(tx, "new", "", nil) }); e != nil {
		t.Fatal(e)
	}
	stream := &Stream{DB: s.DB}
	first, last, e := stream.Bounds()
	if e != nil || first != MaxRows+1 || last != MaxRows+2 {
		t.Fatalf("%d %d %v", first, last, e)
	}
	rows, e := stream.Read(first)
	if e != nil || len(rows) != 1 || rows[0].Type != "new" {
		t.Fatal(rows, e)
	}
	s.DB.Model(&models.OutboxEvent{}).Where("id=?", last).Update("created_at", time.Now().UTC().Add(-25*time.Hour))
	rows, e = stream.Read(first)
	if e != nil || len(rows) != 0 {
		t.Fatal("expired event replayed", rows, e)
	}
}
