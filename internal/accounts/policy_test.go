package accounts

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"golang.org/x/crypto/bcrypt"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebAccountMutationsUseStoredPolicy(t *testing.T) {
	if e := initTestDatabase(filepath.Join(t.TempDir(), "test.db")); e != nil {
		t.Fatal(e)
	}
	db := testDB
	admin := models.User{Username: "administrator", Role: "admin"}
	db.Create(&admin)
	c, _ := appconfig.Load(db)
	c.Password.Minimum = 10
	c.Password.Maximum = 40
	db.Save(&c)
	if e := Create(db, &admin, "short-user", "12345678", "viewer"); e == nil {
		t.Fatal("create ignored minimum")
	}
	password := strings.Repeat("a", 35)
	if e := Create(db, &admin, "long-user", password, "viewer"); e != nil {
		t.Fatal(e)
	}
	var target models.User
	db.First(&target, "username = ?", "long-user")
	if e := bcrypt.CompareHashAndPassword([]byte(target.PasswordHash), []byte(password)); e != nil {
		t.Fatal(e)
	}
	c.Password.Maximum = 26
	db.Save(&c)
	if e := Update(db, &admin, target.ID, Edit{Username: target.Username, Role: "viewer", Version: target.AuthVersion, Password: password}, true); e == nil {
		t.Fatal("reset ignored maximum")
	}
	if e := bcrypt.CompareHashAndPassword([]byte(target.PasswordHash), []byte(password)); e != nil {
		t.Fatal("existing password broken")
	}
	if e := Update(db, &admin, target.ID, Edit{Username: target.Username, Role: "viewer", Version: target.AuthVersion, Password: "new-password-123"}, true); e != nil {
		t.Fatal(e)
	}
}
