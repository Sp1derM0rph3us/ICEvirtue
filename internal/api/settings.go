package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/accounts"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/serverlogs"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
)

type pageData struct {
	Title, Error, Notice, CSRF  string
	User                        *models.User
	Target                      models.User
	CanWrite, IsAdmin, Creating bool
	Users                       []models.User
	Logs                        []serverlogs.Entry
	Page, Pages, Previous, Next int
	Total                       int64
}

func homeData(u *models.User) pageData {
	d := pageData{User: u}
	if u != nil {
		d.CanWrite = access.Allows(u.Role, access.Write)
		d.IsAdmin = access.Allows(u.Role, access.ManageUsers)
	}
	return d
}

var settingsPages = []string{"settings", "user_settings", "admin", "admin_users", "admin_user", "admin_logs"}

func parseSettingsPages(fsys fs.FS) (map[string]*template.Template, error) {
	pages := make(map[string]*template.Template)
	for _, name := range settingsPages {
		tmpl, err := template.New("settings_base.html").ParseFS(fsys, "settings_base.html", name+".html")
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		pages[name] = tmpl
	}
	return pages, nil
}

func (a *API) settingsRoutes(r chi.Router) {
	r.Get("/settings", a.settingsPage)
	r.Group(func(r chi.Router) {
		r.Use(requirePermission(access.Write))
		r.Get("/settings/user", a.userSettings)
		r.With(a.requireForm).Post("/settings/user", a.saveUserSettings)
	})
	r.Route("/settings/admin", func(r chi.Router) {
		r.Use(requirePermission(access.ManageUsers))
		r.Get("/", a.adminPage)
		r.Get("/users", a.usersPage)
		r.Get("/users/new", a.newUserPage)
		r.With(a.requireForm).Post("/users", a.createUser)
		r.Get("/users/{userID}", a.editUserPage)
		r.With(a.requireForm).Post("/users/{userID}", a.saveAdminUser)
		r.With(a.requireForm).Post("/users/{userID}/delete", a.deleteUser)
		r.With(requirePermission(access.ReadLogs)).Get("/logs", a.logsPage)
	})
}

// Native forms are processed by the server. No account records or privileged
// forms are bootstrapped into the public or main dashboard page.
func (a *API) requireForm(next http.Handler) http.Handler {
	return a.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || ct != "application/x-www-form-urlencoded" {
			http.Error(w, "expected form data", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		c, ok := UserFromContext(r.Context())
		if !ok || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(auth.CSRFToken(c))) != 1 {
			http.Error(w, "invalid form token; reload the page", http.StatusForbidden)
			return
		}
		// Duplicate fields are ambiguous and never produced by these forms.
		for _, values := range r.PostForm {
			if len(values) != 1 {
				http.Error(w, "duplicate form field", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	}))
}

func (a *API) settingsRender(w http.ResponseWriter, r *http.Request, name, title string, d pageData) {
	d.User = currentUser(r)
	d.Title = title
	d.CanWrite = access.Allows(d.User.Role, access.Write)
	d.IsAdmin = access.Allows(d.User.Role, access.ManageUsers)
	c, _ := UserFromContext(r.Context())
	d.CSRF = auth.CSRFToken(c)
	pages, err := a.pages.get()
	if err != nil {
		log.Printf("[-] Settings template: %v", err)
		http.Error(w, "could not render page", 500)
		return
	}
	a.renderData(w, pages.settings[name], d)
}

func (a *API) settingsPage(w http.ResponseWriter, r *http.Request) {
	a.settingsRender(w, r, "settings", "Settings", pageData{})
}
func (a *API) adminPage(w http.ResponseWriter, r *http.Request) {
	a.settingsRender(w, r, "admin", "Admin dashboard", pageData{})
}
func (a *API) userSettings(w http.ResponseWriter, r *http.Request) {
	a.settingsRender(w, r, "user_settings", "User settings", pageData{Target: *currentUser(r)})
}

func accountError(err error) string {
	var validation accounts.ValidationError
	if errors.As(err, &validation) {
		return validation.Error()
	}
	switch {
	case errors.Is(err, gorm.ErrDuplicatedKey):
		return "That username is already in use."
	case errors.Is(err, gorm.ErrRecordNotFound):
		return "User not found."
	case errors.Is(err, accounts.ErrForbidden):
		return "Your permissions changed. Sign in again."
	case errors.Is(err, accounts.ErrConflict), errors.Is(err, accounts.ErrCredentials), errors.Is(err, accounts.ErrLastAdmin):
		return err.Error()
	default:
		log.Printf("[-] Account operation: %v", err)
		return "The account could not be saved. Check the username, role and password requirements."
	}
}

func editFromForm(r *http.Request) (accounts.Edit, error) {
	e := accounts.Edit{Username: r.PostForm.Get("username"), Password: r.PostForm.Get("password"), Role: r.PostForm.Get("role"), CurrentPassword: r.PostForm.Get("current_password")}
	version, err := strconv.ParseUint(r.PostForm.Get("version"), 10, 64)
	if err != nil || version == 0 {
		return e, accounts.ErrConflict
	}
	e.Version = version
	if e.Password != r.PostForm.Get("confirm_password") {
		return e, accounts.ValidationError("password confirmation does not match")
	}
	return e, nil
}

func (a *API) saveUserSettings(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	edit, err := editFromForm(r)
	if err == nil {
		err = accounts.Update(database.DB, u, u.ID, edit, false)
	}
	if err != nil {
		a.settingsRender(w, r, "user_settings", "User settings", pageData{Target: *u, Error: accountError(err)})
		return
	}
	log.Printf("[+] Account %s updated its credentials; sessions revoked", u.PublicID)
	a.relogin(w, r)
}

func (a *API) relogin(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, a.authCookie("", -1))
	http.Redirect(w, r, "/login?reason=account-updated", http.StatusSeeOther)
}

func pageNumber(r *http.Request, total int64, size int) (int, int) {
	pages := max(1, int((total+int64(size)-1)/int64(size)))
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	return min(max(1, p), pages), pages
}

func (a *API) usersPage(w http.ResponseWriter, r *http.Request) {
	d := pageData{}
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.User{}).Count(&d.Total).Error; err != nil {
			return err
		}
		d.Page, d.Pages = pageNumber(r, d.Total, 50)
		d.Previous = d.Page - 1
		d.Next = d.Page + 1
		return tx.Select("id, username, role, created_at").Order("username ASC, id ASC").Limit(50).Offset((d.Page - 1) * 50).Find(&d.Users).Error
	})
	if err != nil {
		http.Error(w, "could not list users", 500)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "User saved. Existing sessions for an edited user were revoked."
	}
	if r.URL.Query().Get("deleted") == "1" {
		d.Notice = "User deleted and sessions revoked."
	}
	a.settingsRender(w, r, "admin_users", "Users", d)
}

func (a *API) newUserPage(w http.ResponseWriter, r *http.Request) {
	a.settingsRender(w, r, "admin_user", "Create user", pageData{Creating: true, Target: models.User{Role: access.Viewer}})
}

func loadTarget(w http.ResponseWriter, r *http.Request) (*models.User, bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, "userID"), 10, 64)
	if err != nil || id == 0 {
		http.Error(w, "invalid user id", 400)
		return nil, false
	}
	var u models.User
	if err := database.DB.First(&u, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "user not found", 404)
		} else {
			http.Error(w, "could not load user", 500)
		}
		return nil, false
	}
	return &u, true
}

func (a *API) editUserPage(w http.ResponseWriter, r *http.Request) {
	u, ok := loadTarget(w, r)
	if !ok {
		return
	}
	a.settingsRender(w, r, "admin_user", "Edit user", pageData{Target: *u})
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	name, password, role := r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("role")
	var err error
	if password != r.PostForm.Get("confirm_password") {
		err = accounts.ValidationError("password confirmation does not match")
	} else {
		err = accounts.Create(database.DB, u, name, password, role)
	}
	if err != nil {
		a.settingsRender(w, r, "admin_user", "Create user", pageData{Creating: true, Target: models.User{Username: name, Role: role}, Error: accountError(err)})
		return
	}
	log.Printf("[+] Administrator %s created an account with role %s", u.PublicID, role)
	http.Redirect(w, r, "/settings/admin/users?saved=1", http.StatusSeeOther)
}

func (a *API) saveAdminUser(w http.ResponseWriter, r *http.Request) {
	target, ok := loadTarget(w, r)
	if !ok {
		return
	}
	actor := currentUser(r)
	edit, err := editFromForm(r)
	if err == nil {
		err = accounts.Update(database.DB, actor, target.ID, edit, true)
	}
	if err != nil {
		a.settingsRender(w, r, "admin_user", "Edit user", pageData{Target: *target, Error: accountError(err)})
		return
	}
	log.Printf("[+] Administrator %s edited account %s; sessions revoked", actor.PublicID, target.PublicID)
	if target.ID == actor.ID {
		a.relogin(w, r)
		return
	}
	http.Redirect(w, r, "/settings/admin/users?saved=1", http.StatusSeeOther)
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	target, ok := loadTarget(w, r)
	if !ok {
		return
	}
	actor := currentUser(r)
	version, _ := strconv.ParseUint(r.PostForm.Get("version"), 10, 64)
	if r.PostForm.Get("confirm_delete") != "yes" {
		a.settingsRender(w, r, "admin_user", "Edit user", pageData{Target: *target, Error: "Confirm deletion before continuing."})
		return
	}
	if err := accounts.Delete(database.DB, actor, target.ID, version); err != nil {
		a.settingsRender(w, r, "admin_user", "Edit user", pageData{Target: *target, Error: accountError(err)})
		return
	}
	log.Printf("[+] Administrator %s deleted account %s; sessions revoked", actor.PublicID, target.PublicID)
	if target.ID == actor.ID {
		a.relogin(w, r)
		return
	}
	http.Redirect(w, r, "/settings/admin/users?deleted=1", http.StatusSeeOther)
}

func (a *API) logsPage(w http.ResponseWriter, r *http.Request) {
	logs := serverlogs.Default.Snapshot()
	d := pageData{Total: int64(len(logs))}
	d.Page, d.Pages = pageNumber(r, d.Total, 100)
	d.Previous = d.Page - 1
	d.Next = d.Page + 1
	start := (d.Page - 1) * 100
	d.Logs = logs[start:min(start+100, len(logs))]
	a.settingsRender(w, r, "admin_logs", "Server logs", d)
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		started := time.Now()
		defer func() {
			log.Printf("[HTTP] %s %s %d %s", r.Method, r.URL.EscapedPath(), ww.Status(), time.Since(started).Round(time.Millisecond))
		}()
		next.ServeHTTP(ww, r)
	})
}
