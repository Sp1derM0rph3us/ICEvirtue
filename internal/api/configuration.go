package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"reflect"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

var errConfigForbidden = errors.New("session or administrator permission changed; sign in again")

func configAuthorize(r *http.Request) wordlists.Authorize {
	claims, ok := UserFromContext(r.Context())
	return func(tx *gorm.DB) error {
		if !ok || claims.ExpiresAt == nil || !time.Now().Before(claims.ExpiresAt.Time) {
			return errConfigForbidden
		}
		var u models.User
		err := tx.Where("public_id = ? AND auth_version = ? AND role = ?", claims.Subject, claims.Version, access.Admin).
			Where("EXISTS (SELECT 1 FROM sessions WHERE sessions.id = ? AND sessions.user_id = users.id AND julianday(sessions.expires_at) > julianday(?))", claims.ID, time.Now().UTC()).First(&u).Error
		if err != nil {
			return errConfigForbidden
		}
		return nil
	}
}
func requireConfigCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			c, ok := UserFromContext(r.Context())
			if !ok || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(auth.CSRFToken(c))) != 1 {
				http.Error(w, "invalid CSRF token; reload the page", 403)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (a *API) configurationRoutes(r chi.Router) {
	r.Route("/api/admin", func(r chi.Router) {
		r.Use(noStore, a.requireAPIAuth, requirePermission(access.ManageConfiguration), a.requireSameOrigin, requireConfigCSRF)
		r.Get("/configuration", a.getConfiguration)
		r.With(requireJSONBody).Put("/configuration/{section}", a.saveConfiguration)
		r.Get("/wordlists", a.listWordlists)
		r.Post("/wordlists", a.uploadWordlist)
		r.Delete("/wordlists/{wordlistID}", a.deleteWordlist)
	})
}
func configError(w http.ResponseWriter, err error) {
	status := 500
	message := "configuration operation failed"
	var validation appconfig.ValidationError
	switch {
	case errors.Is(err, errConfigForbidden):
		status = 403
		message = err.Error()
	case errors.Is(err, appconfig.ErrConflict), errors.Is(err, wordlists.ErrInUse), errors.Is(err, wordlists.ErrDuplicate):
		status = 409
		message = err.Error()
	case errors.Is(err, wordlists.ErrBusy):
		status = 429
		message = err.Error()
		w.Header().Set("Retry-After", "60")
	case errors.Is(err, wordlists.ErrQuota):
		status = 413
		message = err.Error()
	case errors.Is(err, gorm.ErrRecordNotFound):
		status = 404
		message = "wordlist not found"
	case errors.As(err, &validation):
		status = 400
		message = validation.Error()
	}
	if status == 500 {
		slog.Error("configuration operation failed", "error", err)
	}
	respondJSON(w, status, map[string]string{"error": message})
}
func (a *API) getConfiguration(w http.ResponseWriter, r *http.Request) {
	c, e := appconfig.Load(database.DB)
	if e != nil {
		configError(w, e)
		return
	}
	respondJSON(w, 200, map[string]any{"configuration": c, "limits": map[string]any{"password_minimum": 8, "password_maximum": 72, "password_byte_cap": 72, "max_file_bytes": wordlists.MaxFileBytes, "max_total_bytes": wordlists.MaxTotalBytes, "max_files": wordlists.MaxFiles, "max_queue": 100, "waf_timeout_seconds": []int{1, 300}, "waymore_response_limit": []int{1, 50000}, "max_concurrent_scans": []int{1, 4}}})
}
func (a *API) saveConfiguration(w http.ResponseWriter, r *http.Request) {
	section := chi.URLParam(r, "section")
	var envelope struct {
		Revision uint64          `json:"revision"`
		Settings json.RawMessage `json:"settings"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if e := strictJSON(r.Body, &envelope); e != nil {
		configError(w, appconfig.ValidationError(e.Error()))
		return
	}
	var settings any
	switch section {
	case "password-policy":
		settings = &models.PasswordPolicy{}
	case "scan":
		settings = &models.ScanSettings{}
	case "tools":
		settings = &models.ToolSettings{}
	default:
		http.NotFound(w, r)
		return
	}
	if e := strictJSON(bytes.NewReader(envelope.Settings), settings); e != nil {
		configError(w, appconfig.ValidationError(e.Error()))
		return
	}
	var c models.ApplicationConfiguration
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if e := configAuthorize(r)(tx); e != nil {
			return e
		}
		var e error
		c, e = appconfig.Load(tx)
		if e != nil {
			return e
		}
		switch v := settings.(type) {
		case *models.PasswordPolicy:
			c.Password = *v
		case *models.ScanSettings:
			c.Scan = *v
		case *models.ToolSettings:
			c.Tools = *v
		}
		c.UpdatedBy = currentUser(r).PublicID
		return appconfig.Save(tx, &c, envelope.Revision)
	})
	if err != nil {
		configError(w, err)
		return
	}
	slog.Info("application configuration saved", "actor", c.UpdatedBy, "section", section, "revision", c.Revision, "settings", settings)
	respondJSON(w, 200, c)
}

// Strict decoding rejects duplicate keys, missing fields, nulls, unknown fields,
// and multiple JSON values. The limited body keeps this validation bounded.
func strictJSON(r io.Reader, dst any) error {
	b, e := io.ReadAll(r)
	if e != nil {
		return errors.New("invalid or oversized JSON body")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if e = uniqueJSON(dec, 0); e != nil {
		return e
	}
	if _, e = dec.Token(); e != io.EOF {
		return errors.New("trailing JSON is not allowed")
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(b, &fields); e != nil || fields == nil {
		return errors.New("expected a JSON object")
	}
	t := reflect.TypeOf(dst).Elem()
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Tag.Get("json")
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("all section fields are required and cannot be null")
		}
	}
	dec = json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(dst); e != nil {
		return errors.New("unknown field or invalid value type")
	}
	return nil
}
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("JSON nesting is too deep")
	}
	tok, e := d.Token()
	if e != nil {
		return errors.New("invalid JSON")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			k, ok := key.(string)
			if !ok || seen[k] {
				return errors.New("duplicate JSON property")
			}
			seen[k] = true
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return errors.New("invalid JSON")
	}
	_, e = d.Token()
	return e
}
func (a *API) listWordlists(w http.ResponseWriter, r *http.Request) {
	items := []models.Wordlist{}
	if e := database.DB.Where("state = ?", "ready").Order("created_at DESC").Limit(wordlists.MaxFiles).Find(&items).Error; e != nil {
		configError(w, e)
		return
	}
	respondJSON(w, 200, items)
}
func (a *API) uploadWordlist(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Wordlists == nil {
		http.Error(w, "wordlist storage unavailable", 503)
		return
	}
	select {
	case a.uploads <- struct{}{}:
		defer func() { <-a.uploads }()
	default:
		configError(w, wordlists.ErrBusy)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Hour)
	defer cancel()
	rc := http.NewResponseController(w)
	defer rc.SetReadDeadline(time.Time{})
	r.Body = http.MaxBytesReader(w, r.Body, wordlists.MaxFileBytes+(64<<10))
	r.Body = &deadlineBody{ReadCloser: r.Body, rc: rc, end: time.Now().Add(time.Hour)}
	mr, e := r.MultipartReader()
	if e != nil {
		configError(w, appconfig.ValidationError("expected multipart file upload"))
		return
	}
	part, e := mr.NextPart()
	if e != nil || part.FormName() != "file" || part.FileName() == "" {
		configError(w, appconfig.ValidationError("expected one file field named file"))
		return
	}
	reader := &singlePartReader{part: part, mr: mr}
	item, e := a.cfg.Wordlists.Upload(ctx, part.FileName(), r.URL.Query().Get("kind"), currentUser(r).PublicID, reader, configAuthorize(r))
	if e != nil {
		configError(w, e)
		return
	}
	slog.Info("wordlist uploaded", "actor", currentUser(r).PublicID, "id", item.ID, "kind", item.Kind, "bytes", item.Bytes, "sha256", item.SHA256)
	respondJSON(w, 201, item)
}

type singlePartReader struct {
	part *multipart.Part
	mr   *multipart.Reader
	done bool
}

func (s *singlePartReader) Read(b []byte) (int, error) {
	n, e := s.part.Read(b)
	if e == io.EOF && !s.done {
		s.done = true
		_, extra := s.mr.NextPart()
		if extra != io.EOF {
			return n, errors.New("only one file is allowed")
		}
	}
	return n, e
}

type deadlineBody struct {
	io.ReadCloser
	rc  *http.ResponseController
	end time.Time
}

func (d *deadlineBody) Read(b []byte) (int, error) {
	deadline := time.Now().Add(time.Minute)
	if d.end.Before(deadline) {
		deadline = d.end
	}
	_ = d.rc.SetReadDeadline(deadline)
	return d.ReadCloser.Read(b)
}
func (a *API) deleteWordlist(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Wordlists == nil {
		http.Error(w, "wordlist storage unavailable", 503)
		return
	}
	id := chi.URLParam(r, "wordlistID")
	if e := a.cfg.Wordlists.Delete(id, configAuthorize(r)); e != nil {
		configError(w, e)
		return
	}
	slog.Info("wordlist deleted", "actor", currentUser(r).PublicID, "id", id)
	w.WriteHeader(204)
}
