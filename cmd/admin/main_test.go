package main

import (
	"path/filepath"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func TestCreateAdmin(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "accounts.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}

	const username = "bootstrap.admin"
	const password = "correct-horse-battery"
	if err := createAdmin(db, username, password); err != nil {
		t.Fatal(err)
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if user.Role != access.Admin || user.AuthVersion != 1 {
		t.Fatalf("admin account has role %q and auth version %d", user.Role, user.AuthVersion)
	}
	if _, err := uuid.Parse(user.PublicID); err != nil {
		t.Fatalf("admin account has invalid public ID %q: %v", user.PublicID, err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		t.Fatalf("admin account has unusable password hash: %v", err)
	}
	if user.PasswordHash == password {
		t.Fatal("password was stored in plain text")
	}

	if err := createAdmin(db, username, password); err == nil {
		t.Fatal("duplicate username was accepted")
	}
	if err := createAdmin(db, "x", password); err == nil {
		t.Fatal("invalid username was accepted")
	}
	if err := createAdmin(db, "another.admin", "short"); err == nil {
		t.Fatal("short password was accepted")
	}
}
