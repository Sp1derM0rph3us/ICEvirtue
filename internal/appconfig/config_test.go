package appconfig_test

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnicodePasswordPolicy(t *testing.T) {
	p := models.PasswordPolicy{Minimum: 8, Maximum: 26}
	for _, test := range []struct {
		password string
		valid    bool
	}{{"12345678", true}, {strings.Repeat("a", 26), true}, {strings.Repeat("a", 27), false}, {strings.Repeat("é", 8), true}, {strings.Repeat("😀", 18), true}, {strings.Repeat("😀", 19), false}, {"abc\xff12345", false}, {"1234567", false}} {
		e := appconfig.ValidatePassword(p, test.password)
		if (e == nil) != test.valid {
			t.Errorf("%d bytes valid=%v got %v", len(test.password), test.valid, e)
		}
	}
}
func TestSeedDoesNotOverwriteSavedConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	if e := database.InitDatabase(path); e != nil {
		t.Fatal(e)
	}
	db := database.DB
	c, _ := appconfig.Load(db)
	c.Password.Maximum = 40
	if e := db.Save(&c).Error; e != nil {
		t.Fatal(e)
	}
	if e := appconfig.Seed(db); e != nil {
		t.Fatal(e)
	}
	sqlDB, _ := db.DB()
	sqlDB.Close()
	if e := database.InitDatabase(path); e != nil {
		t.Fatal(e)
	}
	c, e := appconfig.Load(database.DB)
	if e != nil || c.Password.Maximum != 40 {
		t.Fatalf("restart lost settings: %+v %v", c, e)
	}
}
