package accounts

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"gorm.io/gorm"
)

var testDB *gorm.DB

func initTestDatabase(path string) error {
	s, e := database.Open(path, true)
	if e == nil {
		testDB = s.DB
	}
	return e
}
