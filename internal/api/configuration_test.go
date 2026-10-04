package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
)

func configurationServer(t *testing.T) (http.Handler, *wordlists.Store) {
	t.Helper()
	newAPIEnv(t)
	initAuth(t)
	store, e := wordlists.New(database.DB, filepath.Join(t.TempDir(), "uploads"), "../../web")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	h, e := NewRouter(Config{Templates: os.DirFS("../../web/templates"), Static: os.DirFS("../../web/static"), Wordlists: store, SessionTTL: time.Hour}, nil)
	if e != nil {
		t.Fatal(e)
	}
	return h, store
}
func configRequest(t *testing.T, h http.Handler, method, path, body string, cookie *http.Cookie, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://example.com")
	if cookie != nil {
		r.AddCookie(cookie)
		if csrf {
			claims, e := auth.ValidateToken(cookie.Value)
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("X-CSRF-Token", auth.CSRFToken(claims))
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestConfigurationAuthorizationAndStrictUpdates(t *testing.T) {
	h, _ := configurationServer(t)
	_, admin := roleUser(t, "admin")
	for _, role := range []string{"viewer", "operator"} {
		_, cookie := roleUser(t, role)
		for _, path := range []string{"/api/admin/configuration", "/api/admin/wordlists", "/settings/admin/configuration"} {
			requireStatus(t, do(t, h, "GET", path, cookie), 403)
		}
		requireStatus(t, configRequest(t, h, "PUT", "/api/admin/configuration/password-policy", `{"revision":1,"settings":{"minimum":10,"maximum":30}}`, cookie, true), 403)
	}
	requireStatus(t, do(t, h, "GET", "/settings/admin/configuration", admin), 200)
	const path = "/api/admin/configuration/password-policy"
	valid := `{"revision":1,"settings":{"minimum":10,"maximum":30}}`
	requireStatus(t, configRequest(t, h, "PUT", path, valid, admin, false), 403)
	for _, body := range []string{`{"revision":1,"revision":2,"settings":{"minimum":10,"maximum":30}}`, `{"revision":1,"settings":{"minimum":10,"minimum":12,"maximum":30}}`, `{"revision":1,"settings":{"minimum":10,"maximum":30,"role":"admin"}}`, `{"revision":1,"settings":{"minimum":10}}`, `{"revision":1,"settings":{"minimum":null,"maximum":30}}`, valid + `{}`, `{"revision":1,"settings":{"minimum":7,"maximum":30}}`} {
		requireStatus(t, configRequest(t, h, "PUT", path, body, admin, true), 400)
	}
	requireStatus(t, configRequest(t, h, "PUT", path, valid, admin, true), 200)
	requireStatus(t, configRequest(t, h, "PUT", path, valid, admin, true), 409)
	c, e := appconfig.Load(database.DB)
	if e != nil || c.Revision != 2 || c.Password.Minimum != 10 || c.Password.Maximum != 30 {
		t.Fatalf("settings not persisted: %+v %v", c, e)
	}
	// Existing credentials remain valid under the tightened policy.
	c.Password.Minimum = 25
	if e = database.DB.Save(&c).Error; e != nil {
		t.Fatal(e)
	}
	requireStatus(t, do(t, h, "GET", "/api/admin/configuration", admin), 200)
	claims, _ := auth.ValidateToken(admin.Value)
	database.DB.Delete(&models.Session{}, "id = ?", claims.ID)
	requireStatus(t, do(t, h, "GET", "/api/admin/configuration", admin), 401)
}
func TestConfigurationConcurrentRevisionAndCrossOrigin(t *testing.T) {
	h, _ := configurationServer(t)
	_, cookie := roleUser(t, "admin")
	body := `{"revision":1,"settings":{"waf_timeout_seconds":45,"waymore_response_limit":100,"max_concurrent_scans":3,"subfinder_timeout_minutes":20,"amass_timeout_minutes":60,"dnsx_timeout_minutes":30,"httpx_timeout_minutes":30,"nuclei_timeout_minutes":120,"waymore_timeout_minutes":60,"katana_timeout_minutes":45,"subjs_timeout_minutes":15,"mantra_timeout_minutes":30,"secrethound_timeout_minutes":30,"fuzzer_timeout_minutes":120}}`
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- configRequest(t, h, "PUT", "/api/admin/configuration/tools", body, cookie, true).Code
		}()
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[200] != 1 || counts[409] != 1 {
		t.Fatalf("lost update protection: %v", counts)
	}
	r := httptest.NewRequest("PUT", "/api/admin/configuration/tools", strings.NewReader(body))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://attacker.invalid")
	claims, _ := auth.ValidateToken(cookie.Value)
	r.Header.Set("X-CSRF-Token", auth.CSRFToken(claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	requireStatus(t, w, 403)
}
func TestWordlistAPIUploadSelectionAndDelete(t *testing.T) {
	h, store := configurationServer(t)
	_, cookie := roleUser(t, "admin")
	upload := func(extra bool) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		part, _ := writer.CreateFormFile("file", "list.txt")
		part.Write([]byte("admin\nlogin\n"))
		if extra {
			part, _ = writer.CreateFormFile("file", "extra.txt")
			part.Write([]byte("extra\n"))
		}
		writer.Close()
		r := httptest.NewRequest("POST", "/api/admin/wordlists?kind=directory", &buf)
		r.Header.Set("Content-Type", writer.FormDataContentType())
		r.AddCookie(cookie)
		claims, _ := auth.ValidateToken(cookie.Value)
		r.Header.Set("X-CSRF-Token", auth.CSRFToken(claims))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	requireStatus(t, upload(true), 400)
	w := upload(false)
	requireStatus(t, w, 201)
	var item models.Wordlist
	if e := json.Unmarshal(w.Body.Bytes(), &item); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(w.Body.String(), store.Path) || strings.Contains(w.Body.String(), "filename") {
		t.Fatal("filesystem metadata leaked")
	}
	c, _ := appconfig.Load(database.DB)
	c.Scan.SkipDirectory = false
	c.Scan.DirectoryWordlists = []string{item.ID}
	raw, _ := json.Marshal(map[string]any{"revision": c.Revision, "settings": c.Scan})
	requireStatus(t, configRequest(t, h, "PUT", "/api/admin/configuration/scan", string(raw), cookie, true), 200)
	requireStatus(t, configRequest(t, h, "DELETE", "/api/admin/wordlists/"+item.ID, "", cookie, true), 409)
	c, _ = appconfig.Load(database.DB)
	c.Scan.SkipDirectory = true
	c.Scan.DirectoryWordlists = []string{}
	raw, _ = json.Marshal(map[string]any{"revision": c.Revision, "settings": c.Scan})
	requireStatus(t, configRequest(t, h, "PUT", "/api/admin/configuration/scan", string(raw), cookie, true), 200)
	requireStatus(t, configRequest(t, h, "DELETE", "/api/admin/wordlists/"+item.ID, "", cookie, true), 204)
	requireStatus(t, configRequest(t, h, "DELETE", "/api/admin/wordlists/"+item.ID, "", cookie, true), 404)
	c.Scan.DNSXWordlists = []string{"unknown"}
	raw, _ = json.Marshal(map[string]any{"revision": 3, "settings": c.Scan})
	requireStatus(t, configRequest(t, h, "PUT", "/api/admin/configuration/scan", string(raw), cookie, true), 400)
}
func TestConfigCommitRejectsRevokedSession(t *testing.T) {
	h, _ := configurationServer(t)
	u, cookie := roleUser(t, "admin")
	_ = h
	claims, _ := auth.ValidateToken(cookie.Value)
	r := httptest.NewRequest("PUT", "/", nil)
	r = r.WithContext(authenticatedContext(r, claims, u))
	authorize := configAuthorize(r)
	if e := authorize(database.DB); e != nil {
		t.Fatal(e)
	}
	database.DB.Delete(&models.Session{}, "id = ?", claims.ID)
	if e := authorize(database.DB); e == nil {
		t.Fatal("revoked session accepted at commit")
	}
}
func TestPasswordFormShowsPolicyWithoutTruncation(t *testing.T) {
	h, _ := configurationServer(t)
	_, cookie := roleUser(t, "admin")
	for _, path := range []string{"/settings/admin/users/new", "/settings/user"} {
		w := do(t, h, "GET", path, cookie)
		requireStatus(t, w, 200)
		body := w.Body.String()
		if !strings.Contains(body, "8–26") || strings.Contains(body, `maxlength="72"`) {
			t.Fatal(fmt.Sprintf("incorrect password policy markup at %s", path))
		}
		if strings.Count(body, "new TextEncoder()") != 1 {
			t.Fatal("missing or repeated password counter")
		}
	}
}

func TestDisabledScheduleRemovesOnlyScheduledQueueEntry(t *testing.T) {
	h, _ := configurationServer(t)
	_, cookie := roleUser(t, "admin")
	var profile models.Profile
	database.DB.First(&profile)
	database.DB.Model(&profile).Update("is_queued", true)
	database.DB.Create(&models.ScanJob{ProfileID: profile.ID.String(), Source: "scheduled", State: "queued"})
	body := `{"schedule":"@every 24h","enabled":false}`
	requireStatus(t, configRequest(t, h, "PUT", "/api/profiles/"+profile.ID.String()+"/schedule", body, cookie, true), 200)
	var n int64
	database.DB.Model(&models.ScanJob{}).Count(&n)
	database.DB.First(&profile, "id = ?", profile.ID)
	if n != 0 || profile.Enabled || profile.IsQueued {
		t.Fatal("scheduled job survived disable")
	}
	database.DB.Model(&profile).Update("is_queued", true)
	database.DB.Create(&models.ScanJob{ProfileID: profile.ID.String(), Source: "manual", State: "queued"})
	requireStatus(t, configRequest(t, h, "PUT", "/api/profiles/"+profile.ID.String()+"/schedule", body, cookie, true), 200)
	database.DB.Model(&models.ScanJob{}).Count(&n)
	if n != 1 {
		t.Fatal("manual request lost when disabling schedule")
	}
	requireStatus(t, configRequest(t, h, "DELETE", "/api/profiles/"+profile.ID.String(), "", cookie, true), 204)
	database.DB.Model(&models.ScanJob{}).Count(&n)
	if n != 0 {
		t.Fatal("queued job survived profile deletion")
	}
}
