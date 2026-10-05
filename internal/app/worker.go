package app

import (
	"context"
	"flag"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"os"
	"os/signal"
	"syscall"
)

func RunWorker(args []string) error {
	f := flag.NewFlagSet("ICEvirtue-worker", flag.ContinueOnError)
	path := f.String("db-path", "icevirtue.db", "Shared SQLite database")
	uploads := f.String("upload-dir", "uploads", "Shared private wordlist directory")
	home := f.String("tool-home", "", "External tool configuration directory")
	paths := f.String("tool-paths", "", "Comma-separated name=path tool overrides")
	waymore := f.String("waymore-config", "", "Waymore configuration file")
	if e := f.Parse(args); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	db, e := database.Open(*path, false)
	if e != nil {
		return e
	}
	defer db.Close()
	store, e := wordlists.OpenWorker(db.DB, *uploads)
	if e != nil {
		return e
	}
	defer store.Close()
	config, e := appconfig.Load(db.DB)
	if e != nil {
		return e
	}
	tools := engine.NewToolchain(*home, *paths, *waymore)
	tools.PreflightTools(config)
	worker := engine.NewCoordinator(db.DB, store)
	worker.SetTools(tools)
	if e = worker.Recover(); e != nil {
		return e
	}
	if e = worker.Queue.Prune(); e != nil {
		return e
	}
	worker.Start()
	defer worker.Stop()
	sched := scheduler.New(db.DB, worker.Owner)
	return sched.Run(ctx)
}
