package api

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
)

func TestSSEReplayResetAndCancellation(t *testing.T) {
	h := newServer(t)
	cookie := sessionCookie(t, time.Hour)
	for i := 0; i < 3; i++ {
		if e := testDB.Transaction(func(tx *gorm.DB) error { return events.Append(tx, "profile_update", fmt.Sprint(i), nil) }); e != nil {
			t.Fatal(e)
		}
	}
	stream := &events.Stream{DB: testDB}
	first, last, e := stream.Bounds()
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	read := func(cursor uint64) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/events", nil)
		req.AddCookie(cookie)
		req.Header.Set("Last-Event-ID", fmt.Sprint(cursor))
		response, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal(response.Status)
		}
		scan := bufio.NewScanner(response.Body)
		var text strings.Builder
		for scan.Scan() {
			line := scan.Text()
			text.WriteString(line + "\n")
			if strings.HasPrefix(line, "data:") {
				break
			}
		}
		if scan.Err() != nil {
			t.Fatal(scan.Err())
		}
		return text.String()
	}
	if got := read(first); !strings.Contains(got, fmt.Sprintf("id: %d", first+1)) || !strings.Contains(got, "profile_update") {
		t.Fatal(got)
	}
	testDB.Model(&models.OutboxEvent{}).Where("id < ?", last).Update("created_at", time.Now().UTC().Add(-25*time.Hour))
	if got := read(0); !strings.Contains(got, "stream_reset") {
		t.Fatal(got)
	}
	if got := read(last + 100); !strings.Contains(got, "stream_reset") {
		t.Fatal(got)
	}
}
