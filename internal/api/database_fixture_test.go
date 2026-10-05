package api

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/accounts"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/notifications"
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

var testSigner = &auth.Signer{}

func testAPI() *API {
	return &API{inbox: &notifications.Service{DB: testDB}, queries: &queryService{db: testDB}, sessions: &accounts.Sessions{DB: testDB, Signer: testSigner}, db: testDB, signer: testSigner, queue: &jobs.Queue{DB: testDB}, stream: &events.Stream{DB: testDB}}
}
