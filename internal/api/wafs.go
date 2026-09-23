package api

import (
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type nodeWAFs struct {
	Names   []string `json:"names"`
	Scanned bool     `json:"scanned"`
}

func getProfileWAFs(w http.ResponseWriter, r *http.Request) {
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
	var values []string
	if err := database.DB.Model(&models.AliveHost{}).
		Distinct("waf_name").
		Where("profile_id = ? AND host = ? AND waf_name IS NOT NULL", id, host).
		Pluck("waf_name", &values).Error; err != nil {
		log.Printf("[-] Summarizing WAF observations for %s/%s: %v", id, host, err)
		http.Error(w, "failed to summarize WAF observations", http.StatusInternalServerError)
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
