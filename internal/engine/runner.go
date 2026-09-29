package engine

import (
	"context"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"time"
)

// runner belongs to one scan. Its settings and wordlist paths never change.
type runner struct {
	ctx                       context.Context
	config                    models.ApplicationConfiguration
	dnsxPaths, directoryPaths []string
	wafTimeout                time.Duration
	claimed                   bool
	scratch                   string
}
