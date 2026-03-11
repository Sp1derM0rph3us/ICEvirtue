package engine

import (
	"log"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

var Verbose bool

var DnsxList string

var DirectoryList string

var SkipAmass bool

var SkipNuclei bool

func OrchestrateScan(profile *models.Profile) {
	var p models.Profile
	if err := database.DB.First(&p, profile.ID).Error; err != nil {
		log.Printf("[-] Profile %d not found in DB before scan", profile.ID)
		return
	}

	if p.IsScanning {
		log.Printf("[-] Skipping scan for %s. A scan is already currently running.", profile.Domain)
		return
	}

	database.DB.Model(&p).Update("is_scanning", true)
	events.Broadcast("profile_update", p.ID.String(), nil)
	defer func() {
		database.DB.Model(&p).Update("is_scanning", false)
		events.Broadcast("profile_update", p.ID.String(), nil)
	}()

	log.Printf("======================")
	log.Printf("[+] INITIATING SCAN PIPELINE for Profile: %s", profile.Domain)
	log.Printf("======================")

	subdomains, err := RunSubfinder(profile)
	if err != nil {
		log.Printf("[-] Critical Error in Subfinder Phase: %v", err)
		return
	}

	uniqueSubs := make(map[string]bool)
	var finalSubdomains []string

	for _, sub := range subdomains {
		if !uniqueSubs[sub] {
			uniqueSubs[sub] = true
			finalSubdomains = append(finalSubdomains, sub)
		}
	}

	if profile.Mode == "full" {
		log.Printf("[*] [Target: %s] Full Mode Enabled. Executing Active Subdomain Enumeration...", profile.Domain)
		
		if !SkipAmass {
			amassSubs, err := RunAmass(profile)
			if err != nil {
				log.Printf("[-] Error in Amass Phase: %v", err)
			} else {
				for _, sub := range amassSubs {
					if !uniqueSubs[sub] {
						uniqueSubs[sub] = true
						finalSubdomains = append(finalSubdomains, sub)
					}
				}
			}
		} else {
			log.Printf("[*] [Target: %s] Skipping Amass execution as requested via flags.", profile.Domain)
		}

		if DnsxList != "" {
			dnsxSubs, err := RunDnsx(profile, DnsxList)
			if err != nil {
				log.Printf("[-] Error in Dnsx Phase: %v", err)
			} else {
				for _, sub := range dnsxSubs {
					if !uniqueSubs[sub] {
						uniqueSubs[sub] = true
						finalSubdomains = append(finalSubdomains, sub)
					}
				}
			}
		} else {
			log.Printf("[-] Skipping dnsx bruteforce: No --dnsx-list provided.")
		}
	}

	if len(finalSubdomains) == 0 {
		log.Printf("[-] No subdomains found for %s. Halting pipeline.", profile.Domain)
		return
	}
	
	newSubdomains := diffSubdomains(&profile.ID, finalSubdomains)
	if newSubdomains > 0 {
		events.Broadcast("discovery_update", profile.ID.String(), nil)
	}

	hosts, err := RunHttpx(profile, finalSubdomains)
	if err != nil {
		log.Printf("[-] Critical Error in Httpx Phase: %v", err)
		return
	}

	if len(hosts) == 0 {
		log.Printf("[-] No alive hosts found for %s. Halting pipeline.", profile.Domain)
		return
	}

	newHosts := diffHosts(&profile.ID, hosts)
	if newHosts > 0 {
		events.Broadcast("discovery_update", profile.ID.String(), nil)
	}

	var validHosts []models.AliveHost
	for _, h := range hosts {
		if h.StatusCode == 200 || h.StatusCode == 301 || h.StatusCode == 302 || h.StatusCode == 307 {
			validHosts = append(validHosts, h)
		}
	}

	// Phase 2: Directory Fuzzing
	var dirs []models.DirectoryFinding
	if DirectoryList != "" {
		dirs, err = RunDirectoryFuzzing(profile, validHosts, DirectoryList)
		if err != nil {
			log.Printf("[-] Error in Directory Fuzzing Phase: %v", err)
		}
	} else {
		log.Printf("[-] Skipping directory fuzzing: No --directory-list provided.")
	}

	newDirs := diffDirectories(&profile.ID, dirs)
	if newDirs > 0 {
		events.Broadcast("discovery_update", profile.ID.String(), nil)
	}

	// Phase 3: Nuclei
	var vulns []models.Vulnerability
	if !SkipNuclei {
		var err error
		vulns, err = RunNuclei(profile, validHosts)
		if err != nil {
			log.Printf("[-] Error in Nuclei Phase: %v", err)
		}
	} else {
		log.Printf("[*] [Target: %s] Skipping Nuclei execution as requested via flags.", profile.Domain)
	}

	newVulns := diffVulns(&profile.ID, vulns)
	if newVulns > 0 {
		events.Broadcast("discovery_update", profile.ID.String(), nil)
	}

	// Phase 4: Secrets Hunting
	secrets, err := RunSourceReviewPipeline(profile, validHosts, finalSubdomains)
	if err != nil {
		log.Printf("[-] Error in Source Review Phase: %v", err)
	}

	newSecrets := diffSecrets(&profile.ID, secrets)
	if newSecrets > 0 {
		events.Broadcast("discovery_update", profile.ID.String(), nil)
	}

	log.Printf("======================")
	log.Printf("[+] PIPELINE COMPLETE for %s", profile.Domain)
	log.Printf("[+] New Subdomains: %d", newSubdomains)
	log.Printf("[+] New Alive Hosts: %d", newHosts)
	log.Printf("[+] New Directories: %d", newDirs)
	log.Printf("[+] New Vulnerabilities: %d", newVulns)
	log.Printf("[+] New Secrets Found: %d", newSecrets)
	log.Printf("======================\n")
}

func diffSubdomains(profileID *uuid.UUID, subdomains []string) int {
	newCount := 0
	for _, sub := range subdomains {
		var existing models.Subdomain
		result := database.DB.Where("profile_id = ? AND domain = ?", *profileID, sub).First(&existing)
		
		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [+] NEW Subdomain: %s", sub)
			}
			database.DB.Create(&models.Subdomain{
				ProfileID: *profileID,
				Domain:    sub,
			})
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Subdomain: %s", sub)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
		}
	}
	return newCount
}

func diffHosts(profileID *uuid.UUID, hosts []models.AliveHost) int {
	newCount := 0
	for _, h := range hosts {
		var existing models.AliveHost
		result := database.DB.Where("profile_id = ? AND url = ?", *profileID, h.URL).First(&existing)
		
		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [+] NEW Alive Host: %s (IP: %s | Title: %s)", h.URL, h.IP, h.Title)
			}
			database.DB.Create(&h)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Alive Host: %s", h.URL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
			
			if h.IP != "" && existing.IP != h.IP {
				database.DB.Model(&existing).Update("IP", h.IP)
			}
			if h.StatusCode != 0 && existing.StatusCode != h.StatusCode {
				database.DB.Model(&existing).Update("StatusCode", h.StatusCode)
			}
		}
	}
	return newCount
}

func diffVulns(profileID *uuid.UUID, vulns []models.Vulnerability) int {
	newCount := 0
	for _, v := range vulns {
		var existing models.Vulnerability
		result := database.DB.Where("profile_id = ? AND template_id = ? AND url = ?", *profileID, v.TemplateID, v.URL).First(&existing)
		
		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [!] NEW Vulnerability: %s found on %s (%s)", v.TemplateID, v.URL, v.Severity)
			}
			database.DB.Create(&v)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Vulnerability: %s found on %s", v.TemplateID, v.URL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
		}
	}
	return newCount
}

func diffSecrets(profileID *uuid.UUID, secrets []models.SecretFinding) int {
	newCount := 0
	for _, s := range secrets {
		var existing models.SecretFinding
		result := database.DB.Where("profile_id = ? AND secret_type = ? AND secret_value = ?", *profileID, s.SecretType, s.SecretValue).First(&existing)
		
		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [!] NEW Secret: %s found in %s", s.SecretType, s.SourceURL)
			}
			database.DB.Create(&s)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Secret: %s found in %s", s.SecretType, s.SourceURL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
		}
	}
	return newCount
}

func diffDirectories(profileID *uuid.UUID, dirs []models.DirectoryFinding) int {
	newCount := 0
	for _, d := range dirs {
		var existing models.DirectoryFinding
		result := database.DB.Where("profile_id = ? AND dir_url = ?", *profileID, d.DirURL).First(&existing)
		
		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [+] NEW Directory: %s (%d)", d.DirURL, d.StatusCode)
			}
			database.DB.Create(&d)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Directory: %s", d.DirURL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
			if existing.StatusCode != d.StatusCode {
				database.DB.Model(&existing).Update("StatusCode", d.StatusCode)
			}
		}
	}
	return newCount
}
