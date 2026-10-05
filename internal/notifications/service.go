package notifications

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
	"time"
)

type Service struct{ DB *gorm.DB }
type Item struct {
	ID        uint      `json:"id"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Host      string    `json:"host"`
	Read      bool      `json:"read"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) List(user uint, limit int) ([]Item, int64, error) {
	rows := []Item{}
	var unread int64
	e := s.DB.Transaction(func(tx *gorm.DB) error {
		if e := tx.Model(&models.Notification{}).Where("user_id=?", user).Order("created_at DESC,id DESC").Limit(limit).Scan(&rows).Error; e != nil {
			return e
		}
		return tx.Model(&models.Notification{}).Where("user_id=? AND read=?", user, false).Count(&unread).Error
	})
	for i := range rows {
		rows[i].CreatedAt = rows[i].CreatedAt.UTC()
	}
	return rows, unread, e
}

// An id of zero selects the authenticated user's entire inbox.
func (s *Service) Change(user, id uint, remove bool) (int64, error) {
	var affected int64
	e := s.DB.Transaction(func(tx *gorm.DB) error {
		query := tx.Model(&models.Notification{}).Where("user_id=?", user)
		if id != 0 {
			query = query.Where("id=?", id)
		}
		var result *gorm.DB
		if remove {
			result = query.Delete(&models.Notification{})
		} else {
			result = query.Update("read", true)
		}
		if result.Error != nil {
			return result.Error
		}
		affected = result.RowsAffected
		if affected == 0 {
			return nil
		}
		return events.Append(tx, "notifications_changed", "", nil)
	})
	return affected, e
}
