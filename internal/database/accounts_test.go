package database

import (
	"path/filepath"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestLegacyUsersMigrateOnceAndNewUsersDefaultToViewer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE users (id integer PRIMARY KEY AUTOINCREMENT, username text NOT NULL, password_hash text NOT NULL, created_at datetime, updated_at datetime, deleted_at datetime)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO users(username,password_hash) VALUES ('first','hash'),('second','hash')`).Error; err != nil {
		t.Fatal(err)
	}
	connection, _ := db.DB()
	connection.Close()
	previous := DB
	t.Cleanup(func() { DB = previous })
	if err := InitDatabase(path); err != nil {
		t.Fatal(err)
	}
	var users []models.User
	if err := DB.Find(&users).Error; err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Role != "admin" || u.AuthVersion != 1 {
			t.Fatalf("legacy account not migrated: %+v", u)
		}
		if _, err := uuid.Parse(u.PublicID); err != nil {
			t.Fatal(err)
		}
	}
	if users[0].PublicID == users[1].PublicID {
		t.Fatal("public id reused")
	}
	u := models.User{Username: "new-user", PasswordHash: "hash"}
	if err := DB.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	if u.Role != "viewer" {
		t.Fatal("new user did not default to viewer")
	}
	// A later corrupted role must never be elevated on restart by the migration.
	DB.Model(&u).Update("role", "")
	connection, _ = DB.DB()
	connection.Close()
	if err := InitDatabase(path); err != nil {
		t.Fatal(err)
	}
	var reloaded models.User
	DB.First(&reloaded, u.ID)
	if reloaded.Role != "" {
		t.Fatal("migration promoted a post-migration invalid role")
	}
	connection, _ = DB.DB()
	connection.Close()
}
