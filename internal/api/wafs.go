package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
)

type nodeWAFs struct {
	Names   []string `json:"names"`
	Scanned bool     `json:"scanned"`
}

func (a *API) getProfileWAFs(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}
	result := nodeWAFs{Names: []string{}}
	host := hostkey.Normalize(r.URL.Query().Get("host"))
	if host == "" {
		respondJSON(w, http.StatusOK, result)
		return
	}
	values, err := a.queries.wafs(id, host)
	if err != nil {
		http.Error(w, "failed to summarize WAF observations", 500)
		return
	}
	result.Scanned = len(values) > 0
	seen := make(map[string]bool, len(values))
	for _, name := range values {
		name = strings.TrimSpace(name)
		key := strings.ToLower(name)
		if name != "" && key != "none" && !seen[key] {
			result.Names = append(result.Names, name)
			seen[key] = true
		}
	}
	sort.Slice(result.Names, func(i, j int) bool {
		return strings.ToLower(result.Names[i]) < strings.ToLower(result.Names[j])
	})
	respondJSON(w, http.StatusOK, result)
}
