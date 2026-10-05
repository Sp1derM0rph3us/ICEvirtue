// Package app composes process-owned dependencies and their lifecycles.
package app

import (
	"context"
	"flag"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/api"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/serverlogs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type origins []string

func (o *origins) String() string { return strings.Join(*o, ",") }
func (o *origins) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		*o = append(*o, v)
	}
	return nil
}
func RunServer(args []string) error {
	log.SetOutput(io.MultiWriter(os.Stderr, serverlogs.Default))
	f := flag.NewFlagSet("ICEvirtue", flag.ContinueOnError)
	dbPath := f.String("db-path", "icevirtue.db", "SQLite database on a local filesystem")
	uploads := f.String("upload-dir", "uploads", "Private shared wordlist directory")
	web := f.String("web-dir", "web", "Dashboard templates and static assets")
	secret := f.String("jwt-secret", "", "JWT signing key file")
	ipv4 := f.String("ipv4", "127.0.0.1", "IPv4 listen address")
	ipv6 := f.String("ipv6", "::1", "IPv6 listen address")
	port := f.Int("api-port", 8888, "Dashboard port")
	secure := f.Bool("secure-cookies", false, "Use Secure session cookies when serving HTTPS")
	ttl := f.Duration("session-ttl", auth.DefaultSessionTTL, "Session lifetime")
	reload := f.Bool("reload-templates", false, "Reload templates for development")
	var trusted origins
	f.Var(&trusted, "trusted-origin", "Additional trusted request origin; repeatable")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("api-port must be 1–65535")
	}
	for _, a := range []struct {
		v  string
		v6 bool
	}{{*ipv4, false}, {*ipv6, true}} {
		ip := net.ParseIP(a.v)
		if ip == nil || (ip.To4() == nil) != a.v6 {
			return fmt.Errorf("invalid listen address %q", a.v)
		}
	}
	if *ttl < time.Second || *ttl > auth.MaxSessionTTL {
		return fmt.Errorf("invalid session lifetime")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	unlock, e := database.LockServer(*dbPath)
	if e != nil {
		return e
	}
	defer unlock()
	db, e := database.Open(*dbPath, true)
	if e != nil {
		return e
	}
	defer db.Close()
	store, e := wordlists.New(db.DB, *uploads, *web)
	if e != nil {
		return e
	}
	defer store.Close()
	if e = store.Reconcile(); e != nil {
		return fmt.Errorf("upload recovery: %w", e)
	}
	signer, e := auth.New(*secret)
	if e != nil {
		return e
	}
	handler, e := api.NewRouter(api.Config{DB: db.DB, Signer: signer, Shutdown: ctx.Done(), Wordlists: store, Templates: api.DirFS(filepath.Join(*web, "templates")), Static: api.DirFS(filepath.Join(*web, "static")), SecureCookies: *secure, TrustedOrigins: trusted, SessionTTL: *ttl, ReloadTemplates: *reload})
	if e != nil {
		return e
	}
	return api.Serve(ctx, *ipv4, *ipv6, *port, handler)
}
