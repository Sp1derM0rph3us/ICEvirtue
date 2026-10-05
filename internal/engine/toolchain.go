package engine

import "sync"

// Toolchain owns worker-local resolution and environment configuration.
type Toolchain struct {
	Home, Paths, WaymoreConfig string
	defaultHome                string
	homeOnce                   sync.Once
	resolvedHome               string
	pathMu                     sync.Mutex
	pathCache                  map[string]resolution
}

func NewToolchain(home, paths, waymore string) *Toolchain {
	return &Toolchain{Home: home, Paths: paths, WaymoreConfig: waymore, defaultHome: "/opt/icevirtue", pathCache: map[string]resolution{}}
}
