// Test adapters preserve existing tool/parser regressions while production uses per-run state.
package engine

import (
	"context"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"io"
	"sync/atomic"
	"time"
)

var Verbose, SkipAmass, SkipNuclei, WideTargets bool
var DnsxList, DirectoryList string
var WaymoreResponseLimit = 5000
var wafProcessTimeout atomic.Int64

func init()                               { wafProcessTimeout.Store(int64(DefaultWAFProcessTimeout)) }
func GetWAFProcessTimeout() time.Duration { return time.Duration(wafProcessTimeout.Load()) }
func SetWAFProcessTimeout(v time.Duration) error {
	if v <= 0 {
		return fmt.Errorf("WAF process timeout must be greater than zero")
	}
	wafProcessTimeout.Store(int64(v))
	return nil
}
func testRunner() *runner {
	c := appconfig.Defaults()
	c.Scan.Verbose = Verbose
	c.Scan.SkipAmass = SkipAmass
	c.Scan.SkipNuclei = SkipNuclei
	c.Scan.WideTargets = WideTargets
	c.Scan.SkipDNSX = false
	c.Scan.SkipDirectory = false
	c.Tools.WaymoreResponseLimit = WaymoreResponseLimit
	return &runner{ctx: context.Background(), config: c, dnsxPaths: splitList(DnsxList), directoryPaths: splitList(DirectoryList), wafTimeout: GetWAFProcessTimeout()}
}
func RunAmass(profile *models.Profile) ([]string, error) { return testRunner().RunAmass(profile) }
func collectWaymore(profile *models.Profile) ([]string, map[string][]archiveEvidence, func(), error) {
	return testRunner().collectWaymore(profile)
}
func RunDnsx(profile *models.Profile, wordlistPath string) ([]string, error) {
	return testRunner().RunDnsx(profile, wordlistPath)
}
func OrchestrateScan(profile *models.Profile) { testRunner().OrchestrateScan(profile) }
func stageDiscovery(profile *models.Profile) ([]string, *stageReport) {
	return testRunner().stageDiscovery(profile)
}
func stageValidation(profile *models.Profile, subdomains []string) ([]models.AliveHost, *stageReport) {
	return testRunner().stageValidation(profile, subdomains)
}
func stageFuzzing(profile *models.Profile, targets []models.AliveHost) (int, *stageReport) {
	return testRunner().stageFuzzing(profile, targets)
}
func stageVulns(profile *models.Profile, targets []models.AliveHost) ([]models.Vulnerability, *stageReport) {
	return testRunner().stageVulns(profile, targets)
}
func targetHosts(profile *models.Profile, hosts []models.AliveHost) []models.AliveHost {
	return testRunner().targetHosts(profile, hosts)
}
func persistSubdomains(profile *models.Profile, subdomains []string) int {
	return testRunner().persistSubdomains(profile, subdomains)
}
func persistHosts(profile *models.Profile, hosts []models.AliveHost) int {
	return testRunner().persistHosts(profile, hosts)
}
func persistWAFs(profile *models.Profile, observations []wafObservation) int {
	return testRunner().persistWAFs(profile, observations)
}
func persistDirectories(profile *models.Profile, dirs []models.DirectoryFinding) int {
	return testRunner().persistDirectories(profile, dirs)
}
func persistVulns(profile *models.Profile, vulns []models.Vulnerability) int {
	return testRunner().persistVulns(profile, vulns)
}
func persistSecrets(profile *models.Profile, secrets []models.SecretFinding) int {
	return testRunner().persistSecrets(profile, secrets)
}
func diffSubdomains(profileID *uuid.UUID, subdomains []string) int {
	return testRunner().diffSubdomains(profileID, subdomains)
}
func diffHosts(profileID *uuid.UUID, hosts []models.AliveHost) int {
	return testRunner().diffHosts(profileID, hosts)
}
func diffWAFs(profileID *uuid.UUID, observations []wafObservation) int {
	return testRunner().diffWAFs(profileID, observations)
}
func diffVulns(profileID *uuid.UUID, vulns []models.Vulnerability) int {
	return testRunner().diffVulns(profileID, vulns)
}
func diffSecrets(profileID *uuid.UUID, secrets []models.SecretFinding) int {
	return testRunner().diffSecrets(profileID, secrets)
}
func diffDirectories(profileID *uuid.UUID, dirs []models.DirectoryFinding) int {
	return testRunner().diffDirectories(profileID, dirs)
}
func runTool(name string, args []string, stdin io.Reader, timeout time.Duration) (io.ReadCloser, error) {
	return testRunner().runTool(name, args, stdin, timeout)
}
func runToolToFiles(name string, args []string, timeout time.Duration) error {
	return testRunner().runToolToFiles(name, args, timeout)
}
func runToolWithCapture(name string, args []string, stdin io.Reader, timeout time.Duration, captureStdout bool) (io.ReadCloser, error) {
	return testRunner().runToolWithCapture(name, args, stdin, timeout, captureStdout)
}
func RunDirectoryFuzzing(profile *models.Profile, validHosts []models.AliveHost, wordlistPaths []string) (int, error) {
	return testRunner().RunDirectoryFuzzing(profile, validHosts, wordlistPaths)
}
func RunHttpx(profile *models.Profile, subdomains []string) ([]models.AliveHost, error) {
	return testRunner().RunHttpx(profile, subdomains)
}
func RunNuclei(profile *models.Profile, hosts []models.AliveHost) ([]models.Vulnerability, error) {
	return testRunner().RunNuclei(profile, hosts)
}
func stageSecrets(profile *models.Profile, targets []models.AliveHost) ([]models.SecretFinding, *stageReport) {
	return testRunner().stageSecrets(profile, targets)
}
func collectJSSources(profile *models.Profile, targets []models.AliveHost) jsSources {
	return testRunner().collectJSSources(profile, targets)
}
func validateJSURLs(profile *models.Profile, urls []string) ([]string, error) {
	return testRunner().validateJSURLs(profile, urls)
}
func collectKatana(profile *models.Profile, hostURLs []string) ([]string, error) {
	return testRunner().collectKatana(profile, hostURLs)
}
func collectSubjs(profile *models.Profile, hostURLs []string) ([]string, error) {
	return testRunner().collectSubjs(profile, hostURLs)
}
func scanWithMantra(profile *models.Profile, jsURLs []string) ([]models.SecretFinding, error) {
	return testRunner().scanWithMantra(profile, jsURLs)
}
func scanWithSecretHound(profile *models.Profile, jsURLs []string) ([]models.SecretFinding, error) {
	return testRunner().scanWithSecretHound(profile, jsURLs)
}
func scanWithSecretHoundSources(profile *models.Profile, jsURLs []string, archived map[string][]archiveEvidence) ([]models.SecretFinding, error) {
	return testRunner().scanWithSecretHoundSources(profile, jsURLs, archived)
}
func RunSubfinder(profile *models.Profile) ([]string, error) {
	return testRunner().RunSubfinder(profile)
}
func detectWAF(endpoint string, processTimeout time.Duration) (string, error) {
	return testRunner().detectWAF(endpoint, processTimeout)
}
func RunWAFDetection(hosts []models.AliveHost) ([]wafObservation, error) {
	return testRunner().RunWAFDetection(hosts)
}
