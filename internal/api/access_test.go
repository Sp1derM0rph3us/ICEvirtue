package api

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/serverlogs"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const accountPassword = "test-password-1234"

func realServer(t *testing.T) http.Handler {
	t.Helper()
	newAPIEnv(t)
	initAuth(t)
	h, err := NewRouter(Config{Templates: os.DirFS("../../web/templates"), Static: os.DirFS("../../web/static"), SessionTTL: time.Hour}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func roleUser(t *testing.T, role string) (*models.User, *http.Cookie) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(accountPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{Username: role + "-" + uuid.NewString()[:8], PasswordHash: string(hash), Role: role}
	if err := database.DB.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	raw, err := issueSession(u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := auth.ValidateToken(raw)
	if _, err := sessionUser(claims); err != nil {
		var sessions []models.Session
		database.DB.Find(&sessions)
		t.Fatalf("new session invalid: %v user=%d subject=%s version=%d sessions=%+v", err, u.ID, u.PublicID, u.AuthVersion, sessions)
	}
	return u, &http.Cookie{Name: cookieName, Value: raw}
}
func formValues(t *testing.T, cookie *http.Cookie, values url.Values) url.Values {
	t.Helper()
	c, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	values.Set("csrf", auth.CSRFToken(c))
	return values
}
func formRequest(t *testing.T, h http.Handler, path string, cookie *http.Cookie, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func editValues(t *testing.T, c *http.Cookie, u *models.User) url.Values {
	return formValues(t, c, url.Values{"username": {u.Username}, "role": {u.Role}, "version": {fmt.Sprint(u.AuthVersion)}})
}
func requireStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d want %d: %s", w.Code, want, w.Body.String())
	}
}

// Enumerate the actual chi route tree so adding an unguarded endpoint cannot
// quietly escape the authorization regression suite.
func TestEveryRouteRoleBoundary(t *testing.T) {
	h := realServer(t)
	_, viewer := roleUser(t, "viewer")
	_, operator := roleUser(t, "operator")
	err := chi.Walk(h.(chi.Routes), func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		path := strings.ReplaceAll(strings.ReplaceAll(route, "{id}", uuid.NewString()), "{userID}", "999999")
		if strings.HasPrefix(path, "/static/") || path == "/login" || path == "/api/login" || path == "/api/logout" {
			return nil
		}
		t.Run(method+" "+route, func(t *testing.T) {
			want := http.StatusFound
			if strings.HasPrefix(path, "/api/") {
				want = http.StatusUnauthorized
			}
			requireStatus(t, do(t, h, method, path, nil), want)
			if strings.HasPrefix(path, "/settings/admin") || strings.HasPrefix(path, "/settings/user") || (method != "GET" && method != "HEAD") {
				requireStatus(t, do(t, h, method, path, viewer), http.StatusForbidden)
			}
			if strings.HasPrefix(path, "/settings/admin") {
				requireStatus(t, do(t, h, method, path, operator), http.StatusForbidden)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServerRenderedPagesByRole(t *testing.T) {
	h := realServer(t)
	for _, role := range []string{"viewer", "operator", "admin"} {
		t.Run(role, func(t *testing.T) {
			_, c := roleUser(t, role)
			home := do(t, h, "GET", "/", c)
			requireStatus(t, home, 200)
			if !strings.Contains(home.Body.String(), `href="/settings"`) {
				t.Fatal("missing Settings tab")
			}
			if strings.Contains(home.Body.String(), `name="current_password"`) || strings.Contains(home.Body.String(), `name="confirm_password"`) {
				t.Fatal("sensitive forms shipped inside dashboard")
			}
			if role == "viewer" && strings.Contains(home.Body.String(), `id="form-add-target"`) {
				t.Fatal("viewer received create form")
			}
			settings := do(t, h, "GET", "/settings", c)
			requireStatus(t, settings, 200)
			if (role == "admin") != strings.Contains(settings.Body.String(), `href="/settings/admin"`) {
				t.Fatal("admin option visibility incorrect")
			}
			if role != "viewer" {
				w := do(t, h, "GET", "/settings/user", c)
				requireStatus(t, w, 200)
				if !strings.Contains(w.Body.String(), `name="csrf"`) {
					t.Fatal("missing server CSRF field")
				}
			}
			if role == "admin" {
				for _, p := range []string{"/settings/admin", "/settings/admin/users", "/settings/admin/users/new", "/settings/admin/logs"} {
					requireStatus(t, do(t, h, "GET", p, c), 200)
				}
			}
		})
	}
	for _, p := range []string{"/static/settings.html", "/static/admin_users.html", "/static/css/../admin.html", "/web/templates/admin.html"} {
		requireStatus(t, do(t, h, "GET", p, nil), 404)
	}
}

func TestOperatorReconWritesAndViewerReads(t *testing.T) {
	h := realServer(t)
	_, op := roleUser(t, "operator")
	_, v := roleUser(t, "viewer")
	r := httptest.NewRequest("POST", "/api/profiles", strings.NewReader(`{"domain":"operator.example","schedule":"@every 24h"}`))
	r.AddCookie(op)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	requireStatus(t, w, 201)
	var p models.Profile
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"/overview", "/subdomains", "/hosts", "/secrets", "/directories", "/wafs", "/vulnerabilities", "/vulnerabilities/severity-summary"} {
		requireStatus(t, do(t, h, "GET", "/api/profiles/"+p.ID.String()+suffix, v), 200)
	}
	r = httptest.NewRequest("PUT", "/api/profiles/"+p.ID.String()+"/schedule", strings.NewReader(`{"schedule":"every week at 10:00"}`))
	r.AddCookie(op)
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	requireStatus(t, w, 200)
	database.DB.Model(&p).Update("is_scanning", true)
	requireStatus(t, do(t, h, "POST", "/api/profiles/"+p.ID.String()+"/scan", op), 409) // reaches scan handler, without executing an external scanner
	database.DB.Model(&p).Update("is_scanning", false)
	requireStatus(t, do(t, h, "DELETE", "/api/profiles/"+p.ID.String(), op), 204)
}

func TestAdminCreatesEditsRevokesAndDeletes(t *testing.T) {
	h := realServer(t)
	admin, ac := roleUser(t, "admin")
	target, old := roleUser(t, "operator")
	values := formValues(t, ac, url.Values{"username": {"created-viewer"}, "password": {accountPassword}, "confirm_password": {accountPassword}, "role": {"viewer"}})
	requireStatus(t, formRequest(t, h, "/settings/admin/users", ac, values), 303)
	var created models.User
	if err := database.DB.Where("username = ?", "created-viewer").First(&created).Error; err != nil {
		t.Fatal(err)
	}
	if created.Role != "viewer" || bcrypt.CompareHashAndPassword([]byte(created.PasswordHash), []byte(accountPassword)) != nil {
		t.Fatal("incorrect new user")
	}
	// Every kind of admin edit invalidates previously issued sessions.
	for _, field := range []string{"username", "password", "role", "unchanged save"} {
		values = editValues(t, ac, target)
		switch field {
		case "username":
			values.Set("username", "renamed-operator")
		case "password":
			values.Set("password", "new-password-4567")
			values.Set("confirm_password", "new-password-4567")
		case "role":
			values.Set("role", "viewer")
		}
		requireStatus(t, formRequest(t, h, fmt.Sprintf("/settings/admin/users/%d", target.ID), ac, values), 303)
		requireStatus(t, do(t, h, "GET", "/api/profiles", old), 401)
		requireStatus(t, do(t, h, "GET", "/", old), 302)
		if err := database.DB.First(target, target.ID).Error; err != nil {
			t.Fatal(err)
		}
		raw, err := issueSession(target, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		old = &http.Cookie{Name: cookieName, Value: raw}
	}
	database.DB.Create(&models.Notification{UserID: target.ID, Kind: "test", Title: "test"})
	values = editValues(t, ac, target)
	values.Set("confirm_delete", "yes")
	requireStatus(t, formRequest(t, h, fmt.Sprintf("/settings/admin/users/%d/delete", target.ID), ac, values), 303)
	requireStatus(t, do(t, h, "GET", "/api/profiles", old), 401)
	for _, model := range []interface{}{&models.Session{}, &models.Notification{}} {
		var n int64
		database.DB.Model(model).Where("user_id = ?", target.ID).Count(&n)
		if n != 0 {
			t.Fatal("orphaned user data")
		}
	}
	var n int64
	database.DB.Unscoped().Model(&models.User{}).Where("id = ?", target.ID).Count(&n)
	if n != 0 {
		t.Fatal("user was only soft deleted")
	}
	requireStatus(t, do(t, h, "GET", fmt.Sprintf("/settings/admin/users/%d", admin.ID), ac), 200)
}

func TestSelfServiceRequiresPasswordAndRevokesSessions(t *testing.T) {
	h := realServer(t)
	u, c := roleUser(t, "operator")
	v := editValues(t, c, u)
	v.Set("current_password", "wrong")
	v.Set("role", "admin")
	requireStatus(t, formRequest(t, h, "/settings/user", c, v), 200)
	requireStatus(t, do(t, h, "GET", "/", c), 200)
	v.Set("current_password", accountPassword)
	v.Set("username", "own-renamed")
	v.Set("password", "new-password-1234")
	v.Set("confirm_password", "new-password-1234")
	w := formRequest(t, h, "/settings/user", c, v)
	requireStatus(t, w, 303)
	if w.Header().Get("Location") != "/login?reason=account-updated" {
		t.Fatal("not sent to login")
	}
	requireStatus(t, do(t, h, "GET", "/api/profiles", c), 401)
	database.DB.First(u, u.ID)
	if u.Role != "operator" || u.Username != "own-renamed" {
		t.Fatal("self-service changed role or failed rename")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("new-password-1234")) != nil {
		t.Fatal("password was not saved")
	}
}

func TestFormsCSRFAndDuplicateUser(t *testing.T) {
	h := realServer(t)
	u, c := roleUser(t, "admin")
	_, other := roleUser(t, "admin")
	v := editValues(t, c, u)
	v.Set("csrf", "wrong")
	path := fmt.Sprintf("/settings/admin/users/%d", u.ID)
	requireStatus(t, formRequest(t, h, path, c, v), 403)
	v = formValues(t, other, v)
	requireStatus(t, formRequest(t, h, path, c, v), 403)
	v = editValues(t, c, u)
	v.Add("role", "viewer")
	requireStatus(t, formRequest(t, h, path, c, v), 400)
	v = formValues(t, c, url.Values{"username": {u.Username}, "password": {accountPassword}, "confirm_password": {accountPassword}, "role": {"viewer"}})
	w := formRequest(t, h, "/settings/admin/users", c, v)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "already in use") {
		t.Fatal("duplicate username not surfaced")
	}
	requireStatus(t, do(t, h, "GET", "/", c), 200)
}

func TestLastAdminAndAdminSelfEdit(t *testing.T) {
	h := realServer(t)
	u, c := roleUser(t, "admin")
	v := editValues(t, c, u)
	v.Set("role", "viewer")
	path := fmt.Sprintf("/settings/admin/users/%d", u.ID)
	w := formRequest(t, h, path, c, v)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "last administrator") {
		t.Fatal("last admin demoted")
	}
	v = editValues(t, c, u)
	v.Set("confirm_delete", "yes")
	w = formRequest(t, h, path+"/delete", c, v)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "last administrator") {
		t.Fatal("last admin deleted")
	}
	roleUser(t, "admin")
	v = editValues(t, c, u)
	v.Set("username", "admin-renamed")
	v.Set("password", "admin-new-password")
	v.Set("confirm_password", "admin-new-password")
	requireStatus(t, formRequest(t, h, path, c, v), 303)
	requireStatus(t, do(t, h, "GET", "/settings/admin", c), 302)
	database.DB.First(u, u.ID)
	raw, err := issueSession(u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c = &http.Cookie{Name: cookieName, Value: raw}
	v = editValues(t, c, u)
	v.Set("confirm_delete", "yes")
	requireStatus(t, formRequest(t, h, path+"/delete", c, v), 303)
	requireStatus(t, do(t, h, "GET", "/api/profiles", c), 401)
}

func TestLogoutRevokesCopiedCookieAndJWTContainsNoPII(t *testing.T) {
	h := realServer(t)
	u, c := roleUser(t, "viewer")
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(c.Value, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]interface{}
	json.Unmarshal(payload, &claims)
	if len(claims) != 8 || claims["username"] != nil || claims["role"] != nil || strings.Contains(string(payload), u.Username) {
		t.Fatalf("unexpected JWT payload %s", payload)
	}
	requireStatus(t, do(t, h, "POST", "/api/logout", c), 200)
	requireStatus(t, do(t, h, "GET", "/api/profiles", c), 401)
}

func TestActiveSSEStopsAfterRevocation(t *testing.T) {
	h := realServer(t)
	u, c := roleUser(t, "operator")
	s := httptest.NewServer(h)
	defer s.Close()
	req, _ := http.NewRequest("GET", s.URL+"/api/events", nil)
	req.AddCookie(c)
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	reader := bufio.NewReader(res.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Where("user_id = ?", u.ID).Delete(&models.Session{}).Error; err != nil {
		t.Fatal(err)
	}
	result := make(chan string, 1)
	go func() {
		var text strings.Builder
		for {
			line, err := reader.ReadString('\n')
			text.WriteString(line)
			if err != nil {
				break
			}
		}
		result <- text.String()
	}()
	select {
	case text := <-result:
		if !strings.Contains(text, "session_revoked") {
			t.Fatal("stream closed without re-login event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked SSE kept running")
	}
}

func TestLogOutputEscapedAndAdminOnly(t *testing.T) {
	h := realServer(t)
	_, a := roleUser(t, "admin")
	_, o := roleUser(t, "operator")
	serverlogs.Default.Write([]byte(`<script>alert("log")</script>`))
	requireStatus(t, do(t, h, "GET", "/settings/admin/logs", o), 403)
	w := do(t, h, "GET", "/settings/admin/logs", a)
	requireStatus(t, w, 200)
	if strings.Contains(w.Body.String(), `<script>alert("log")</script>`) {
		t.Fatal("unescaped log HTML")
	}
	if !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("log missing")
	}
}

func TestVersionAndUnknownRoleFailClosed(t *testing.T) {
	h := realServer(t)
	u, c := roleUser(t, "operator")
	if err := database.DB.Model(u).Update("auth_version", u.AuthVersion+1).Error; err != nil {
		t.Fatal(err)
	}
	requireStatus(t, do(t, h, "GET", "/api/profiles", c), 401)
	u, c = roleUser(t, "operator")
	if err := database.DB.Model(u).Update("role", "unrecognized").Error; err != nil {
		t.Fatal(err)
	}
	requireStatus(t, do(t, h, "GET", "/api/profiles", c), 401)
}

func TestStaleAdminFormsAndCrossOriginForm(t *testing.T) {
	h := realServer(t)
	_, a := roleUser(t, "admin")
	u, _ := roleUser(t, "operator")
	path := fmt.Sprintf("/settings/admin/users/%d", u.ID)
	v := editValues(t, a, u)
	r := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
	r.AddCookie(a)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://untrusted.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	requireStatus(t, w, 403)
	requireStatus(t, formRequest(t, h, path, a, v), 303)
	v.Set("username", "stale-overwrite")
	w = formRequest(t, h, path, a, v)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "account changed") {
		t.Fatal("stale form not rejected")
	}
	var target models.User
	database.DB.First(&target, u.ID)
	if target.Username != u.Username {
		t.Fatal("stale form overwrote new state")
	}
	if strings.Contains(w.Body.String(), u.PasswordHash) {
		t.Fatal("password hash exposed")
	}
}

func TestAdminPasswordChangeRequiresNewLoginCredentials(t *testing.T) {
	h := realServer(t)
	u, c := roleUser(t, "admin")
	path := fmt.Sprintf("/settings/admin/users/%d", u.ID)
	v := editValues(t, c, u)
	v.Set("username", "admin-new-login")
	v.Set("password", "replacement-password-1234")
	v.Set("confirm_password", "replacement-password-1234")
	requireStatus(t, formRequest(t, h, path, c, v), 303)
	oldJSON, _ := json.Marshal(map[string]string{"username": u.Username, "password": accountPassword})
	requireStatus(t, postJSON(t, h, "/api/login", string(oldJSON), nil), 401)
	requireStatus(t, postJSON(t, h, "/api/login", `{"username":"admin-new-login","password":"test-password-1234"}`, nil), 401)
	login := postJSON(t, h, "/api/login", `{"username":"admin-new-login","password":"replacement-password-1234"}`, nil)
	requireStatus(t, login, 200)
	requireStatus(t, do(t, h, "GET", "/settings/admin", findCookie(login, cookieName)), 200)
	requireStatus(t, do(t, h, "GET", "/settings/admin", c), 302)
}
