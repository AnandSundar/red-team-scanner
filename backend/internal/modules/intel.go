package modules

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redteam/agentic-scanner/pkg/payloads"
	"github.com/redteam/agentic-scanner/pkg/utils"
)

// ============================================================================
// IntelModule - Threat Intelligence Enrichment
// ============================================================================

// IntelModule performs comprehensive threat intelligence enrichment
type IntelModule struct {
	httpClient *utils.HTTPClient
	cache      *utils.IntelCache
	timeout    time.Duration
	manager    *utils.IntelManager
}

// ThreatIntel represents enriched threat intelligence data
type ThreatIntel struct {
	Source      string                 `json:"source"`
	Category    string                 `json:"category"`
	Confidence  float64                `json:"confidence"`
	Data        map[string]interface{} `json:"data"`
	RawResponse string                 `json:"raw_response"`
	Timestamp   time.Time              `json:"timestamp"`
}

// EnrichmentResult contains all enrichment data for a target
type EnrichmentResult struct {
	Target       string                 `json:"target"`
	IP           string                 `json:"ip,omitempty"`
	Domain       string                 `json:"domain,omitempty"`
	AbuseIPDB    *utils.AbuseIPDBResult `json:"abuseipdb,omitempty"`
	URLhaus      *utils.URLhausResult   `json:"urlhaus,omitempty"`
	Shodan       *utils.ShodanResult    `json:"shodan,omitempty"`
	CVEs         []payloads.CVEEntry    `json:"cves,omitempty"`
	CTLog        *utils.CTResult        `json:"cert_transparency,omitempty"`
	Technologies []TechWithCVEs         `json:"technologies,omitempty"`
	Sources      []string               `json:"sources_checked"`
	Timestamp    time.Time              `json:"timestamp"`
}

// TechWithCVEs represents a technology with associated CVEs
type TechWithCVEs struct {
	Name    string              `json:"name"`
	Version string              `json:"version"`
	CVEs    []payloads.CVEEntry `json:"cves"`
}

// NewIntelModule creates a new threat intelligence module
func NewIntelModule() *IntelModule {
	return &IntelModule{
		httpClient: utils.NewHTTPClient(30 * time.Second),
		cache:      utils.NewIntelCache(1 * time.Hour),
		timeout:    60 * time.Second,
		manager:    utils.NewIntelManager(),
	}
}

// Name returns the module name
func (m *IntelModule) Name() string {
	return "intel"
}

// Description returns the module description
func (m *IntelModule) Description() string {
	return "Threat Intelligence Enrichment - AbuseIPDB, NVD CVE lookup, Shodan InternetDB, URLhaus, Certificate Transparency"
}

// Category returns the module category
func (m *IntelModule) Category() string {
	return "threat_intel"
}

// SupportedTargetTypes returns the target types this module supports
func (m *IntelModule) SupportedTargetTypes() []TargetType {
	return AllTargetTypes // Runs on all target types
}

// Execute runs the threat intelligence enrichment module
func (m *IntelModule) Execute(ctx context.Context, config ModuleConfig) ModuleResult {
	result := ModuleResult{
		Module:    m.Name(),
		Status:    "running",
		StartedAt: time.Now(),
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	findings := []Finding{}
	findingsMu := sync.Mutex{}
	sourcesChecked := []string{}
	sourcesMu := sync.Mutex{}

	// Extract target components
	targetURL, err := url.Parse(config.Target)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Failed to parse target URL: %v", err)
		return result
	}

	domain := targetURL.Hostname()
	ip := m.resolveIP(ctx, domain)

	// Build enrichment result
	enrichmentResult := &EnrichmentResult{
		Target:    config.Target,
		Domain:    domain,
		IP:        ip,
		Timestamp: time.Now(),
	}

	// Run enrichment checks in parallel
	var wg sync.WaitGroup

	// 1. AbuseIPDB Check (if API key configured)
	if m.manager.AbuseIPDB.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip != "" {
				sourcesMu.Lock()
				sourcesChecked = append(sourcesChecked, "abuseipdb")
				sourcesMu.Unlock()

				abuseResult, err := m.manager.AbuseIPDB.CheckIP(ctx, ip)
				if err != nil {
					// Log error but continue
					return
				}
				enrichmentResult.AbuseIPDB = abuseResult

				// Create finding if IP has abuse reports
				if abuseResult.AbuseConfidenceScore > 0 {
					finding := CreateAbuseIPDBFinding(
						m.Name(),
						ip,
						abuseResult.AbuseConfidenceScore,
						abuseResult.TotalReports,
						abuseResult.IsTor,
						abuseResult.Categories,
					)
					findingsMu.Lock()
					findings = append(findings, finding)
					findingsMu.Unlock()
				}
			}
		}()
	}

	// 2. URLhaus Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		sourcesMu.Lock()
		sourcesChecked = append(sourcesChecked, "urlhaus")
		sourcesMu.Unlock()

		urlhausResult, err := m.manager.URLhaus.CheckDomain(ctx, domain)
		if err != nil {
			return
		}
		enrichmentResult.URLhaus = urlhausResult

		// Create finding if domain is malicious
		if urlhausResult.IsMalicious {
			finding := CreateURLhausFinding(
				m.Name(),
				domain,
				urlhausResult.IsMalicious,
				urlhausResult.Threat,
				urlhausResult.Payloads,
			)
			findingsMu.Lock()
			findings = append(findings, finding)
			findingsMu.Unlock()
		}
	}()

	// 3. Shodan InternetDB Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ip != "" {
			sourcesMu.Lock()
			sourcesChecked = append(sourcesChecked, "shodan")
			sourcesMu.Unlock()

			shodanResult, err := m.manager.Shodan.LookupIP(ctx, ip)
			if err != nil {
				return
			}
			enrichmentResult.Shodan = shodanResult

			// Create finding with Shodan data
			finding := CreateShodanFinding(
				m.Name(),
				ip,
				shodanResult.Ports,
				shodanResult.Vulns,
				shodanResult.Tags,
				shodanResult.RiskScore,
			)
			findingsMu.Lock()
			findings = append(findings, finding)
			findingsMu.Unlock()

			// Check CVEs from Shodan against our local database
			for _, cveID := range shodanResult.Vulns {
				if cveData, err := m.lookupLocalCVE(cveID); err == nil {
					finding := CreateCVEFinding(
						m.Name(),
						"Unknown Service",
						"unknown",
						cveData.ID,
						cveData.CVSS,
						cveData.Description,
						payloads.IsKEV(cveID),
					)
					findingsMu.Lock()
					findings = append(findings, finding)
					findingsMu.Unlock()
				}
			}
		}
	}()

	// 4. Certificate Transparency Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		sourcesMu.Lock()
		sourcesChecked = append(sourcesChecked, "cert_transparency")
		sourcesMu.Unlock()

		ctResult, err := m.manager.CT.QueryDomain(ctx, domain)
		if err != nil {
			return
		}
		enrichmentResult.CTLog = ctResult

		// Create finding with CT data
		finding := CreateCertificateTransparencyFinding(
			m.Name(),
			domain,
			ctResult.Count,
			ctResult.Subdomains,
		)
		findingsMu.Lock()
		findings = append(findings, finding)
		findingsMu.Unlock()
	}()

	// 5. Technology CVE Lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sourcesMu.Lock()
		sourcesChecked = append(sourcesChecked, "nvd_cve_lookup")
		sourcesMu.Unlock()

		// Detect technologies from target response
		techs := m.detectTechnologies(ctx, config.Target)

		for _, tech := range techs {
			cves := m.lookupCVEsForTechnology(ctx, tech.Name, tech.Version)
			if len(cves) > 0 {
				techWithCVEs := TechWithCVEs{
					Name:    tech.Name,
					Version: tech.Version,
					CVEs:    cves,
				}
				enrichmentResult.Technologies = append(enrichmentResult.Technologies, techWithCVEs)

				// Create finding for each CVE
				for _, cve := range cves {
					finding := CreateCVEFinding(
						m.Name(),
						tech.Name,
						tech.Version,
						cve.ID,
						cve.CVSS,
						cve.Description,
						payloads.IsKEV(cve.ID),
					)
					findingsMu.Lock()
					findings = append(findings, finding)
					findingsMu.Unlock()
				}
			}
		}
	}()

	// Wait for all checks to complete
	wg.Wait()

	// Create summary finding
	summaryFinding := CreateThreatIntelSummaryFinding(
		m.Name(),
		sourcesChecked,
		len(findings),
		m.enrichmentToMap(enrichmentResult),
	)
	findings = append(findings, summaryFinding)

	result.Findings = findings
	result.Status = "completed"
	now := time.Now()
	result.EndedAt = &now

	return result
}

// resolveIP resolves a domain to its IP address
func (m *IntelModule) resolveIP(ctx context.Context, domain string) string {
	// Check if it's already an IP
	if net.ParseIP(domain) != nil {
		return domain
	}

	// Remove port if present
	host, _, err := net.SplitHostPort(domain)
	if err != nil {
		host = domain
	}

	// Try to resolve
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return ""
	}

	return addrs[0]
}

// detectTechnologies detects technologies from the target
func (m *IntelModule) detectTechnologies(ctx context.Context, target string) []payloads.TechnologyVersion {
	techs := []payloads.TechnologyVersion{}

	// Make HTTP request to target
	resp, err := m.httpClient.Get(ctx, target, nil)
	if err != nil {
		return techs
	}

	// Extract from headers
	if resp.Headers != nil {
		server := resp.Headers.Get("Server")
		if server != "" {
			if tech := payloads.ExtractTechnologyVersion(server); tech != nil {
				techs = append(techs, *tech)
			}
		}

		via := resp.Headers.Get("Via")
		if via != "" {
			if tech := payloads.ExtractTechnologyVersion(via); tech != nil {
				techs = append(techs, *tech)
			}
		}

		xPoweredBy := resp.Headers.Get("X-Powered-By")
		if xPoweredBy != "" {
			if tech := payloads.ExtractTechnologyVersion(xPoweredBy); tech != nil {
				techs = append(techs, *tech)
			}
		}
	}

	// Extract from body if available
	if len(resp.Body) > 0 {
		body := string(resp.Body)
		for _, pattern := range payloads.CommonTechnologyPatterns {
			matches := pattern.VersionRegex.FindStringSubmatch(body)
			if len(matches) >= 2 {
				found := false
				for _, t := range techs {
					if t.Name == pattern.Name {
						found = true
						break
					}
				}
				if !found {
					techs = append(techs, payloads.TechnologyVersion{
						Name:    pattern.Name,
						Version: matches[1],
						Vendor:  pattern.Vendor,
					})
				}
			}
		}
	}

	return techs
}

// lookupCVEsForTechnology looks up CVEs for a specific technology and version
func (m *IntelModule) lookupCVEsForTechnology(ctx context.Context, name, version string) []payloads.CVEEntry {
	results := []payloads.CVEEntry{}

	// First check local database
	localCVEs := payloads.MatchCVEsForTechnology(name, version)
	results = append(results, localCVEs...)

	// Query NVD for additional CVEs
	if m.manager.NVD != nil {
		keyword := fmt.Sprintf("%s %s", name, version)
		nvdResults, err := m.manager.NVD.SearchCVEs(ctx, keyword, 10)
		if err == nil {
			for _, nvdResult := range nvdResults {
				cve := payloads.CVEEntry{
					ID:          nvdResult.ID,
					Severity:    nvdResult.Severity,
					CVSS:        nvdResult.CVSSScore,
					Description: nvdResult.Description,
					References:  nvdResult.References,
					KEV:         payloads.IsKEV(nvdResult.ID),
				}
				results = append(results, cve)
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := []payloads.CVEEntry{}
	for _, cve := range results {
		if !seen[cve.ID] {
			seen[cve.ID] = true
			unique = append(unique, cve)
		}
	}

	return unique
}

// lookupLocalCVE looks up a CVE in the local database
func (m *IntelModule) lookupLocalCVE(cveID string) (*payloads.CVEEntry, error) {
	// Search through all known CVEs
	for _, cves := range payloads.KnownCVEs {
		for _, cve := range cves {
			if cve.ID == cveID {
				return &cve, nil
			}
		}
	}
	return nil, fmt.Errorf("CVE not found in local database: %s", cveID)
}

// enrichmentToMap converts enrichment result to map for storage
func (m *IntelModule) enrichmentToMap(result *EnrichmentResult) map[string]interface{} {
	return map[string]interface{}{
		"target":           result.Target,
		"ip":               result.IP,
		"domain":           result.Domain,
		"sources":          result.Sources,
		"has_abuseipdb":    result.AbuseIPDB != nil,
		"has_urlhaus":      result.URLhaus != nil,
		"has_shodan":       result.Shodan != nil,
		"has_ct_log":       result.CTLog != nil,
		"technology_count": len(result.Technologies),
		"timestamp":        result.Timestamp,
	}
}

// GetAbuseIPDBResult retrieves cached AbuseIPDB data for a target
func (m *IntelModule) GetAbuseIPDBResult(ctx context.Context, ip string) (*utils.AbuseIPDBResult, error) {
	return m.manager.AbuseIPDB.CheckIP(ctx, ip)
}

// GetShodanResult retrieves cached Shodan data for a target
func (m *IntelModule) GetShodanResult(ctx context.Context, ip string) (*utils.ShodanResult, error) {
	return m.manager.Shodan.LookupIP(ctx, ip)
}

// GetURLhausResult retrieves cached URLhaus data for a target
func (m *IntelModule) GetURLhausResult(ctx context.Context, domain string) (*utils.URLhausResult, error) {
	return m.manager.URLhaus.CheckDomain(ctx, domain)
}

// GetNVDResults retrieves CVE data from NVD for a keyword
func (m *IntelModule) GetNVDResults(ctx context.Context, keyword string, limit int) ([]utils.NVDResult, error) {
	return m.manager.NVD.SearchCVEs(ctx, keyword, limit)
}

// GetCTResults retrieves Certificate Transparency data for a domain
func (m *IntelModule) GetCTResults(ctx context.Context, domain string) (*utils.CTResult, error) {
	return m.manager.CT.QueryDomain(ctx, domain)
}

// EnrichFinding adds threat intelligence context to an existing finding
func (m *IntelModule) EnrichFinding(finding *Finding, ctx context.Context, target string) {
	// Parse target
	u, err := url.Parse(target)
	if err != nil {
		return
	}

	domain := u.Hostname()
	ip := m.resolveIP(ctx, domain)

	// Add intel context based on finding category
	switch finding.Category {
	case "port-scan":
		// Enrich port findings with Shodan data
		if ip != "" {
			if shodanResult, err := m.manager.Shodan.LookupIP(ctx, ip); err == nil {
				finding.Evidence.Details["shodan_ports"] = shodanResult.Ports
				finding.Evidence.Details["shodan_vulns"] = shodanResult.Vulns
			}
		}

	case "technology-fingerprinting":
		// Enrich technology findings with CVE data
		if techName, ok := finding.Evidence.Details["technology"].(string); ok {
			version := ""
			if v, ok := finding.Evidence.Details["version"].(string); ok {
				version = v
			}
			cves := m.lookupCVEsForTechnology(ctx, techName, version)
			if len(cves) > 0 {
				finding.Evidence.Details["known_cves"] = cves
				// Update finding severity if critical CVEs found
				for _, cve := range cves {
					if cve.Severity == "Critical" || payloads.IsKEV(cve.ID) {
						finding.Severity = SeverityHigh
						finding.CVEs = append(finding.CVEs, cve.ID)
						if finding.CVSS < cve.CVSS {
							finding.CVSS = cve.CVSS
						}
					}
				}
			}
		}
	}
}

// CheckIPReputation checks the reputation of an IP across all available sources
func (m *IntelModule) CheckIPReputation(ctx context.Context, ip string) map[string]interface{} {
	result := make(map[string]interface{})
	result["ip"] = ip
	result["timestamp"] = time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// AbuseIPDB
	if m.manager.AbuseIPDB.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if abuseResult, err := m.manager.AbuseIPDB.CheckIP(ctx, ip); err == nil {
				mu.Lock()
				result["abuseipdb"] = abuseResult
				mu.Unlock()
			}
		}()
	}

	// Shodan
	wg.Add(1)
	go func() {
		defer wg.Done()
		if shodanResult, err := m.manager.Shodan.LookupIP(ctx, ip); err == nil {
			mu.Lock()
			result["shodan"] = shodanResult
			mu.Unlock()
		}
	}()

	wg.Wait()
	return result
}

// CheckDomainReputation checks the reputation of a domain across all available sources
func (m *IntelModule) CheckDomainReputation(ctx context.Context, domain string) map[string]interface{} {
	result := make(map[string]interface{})
	result["domain"] = domain
	result["timestamp"] = time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// URLhaus
	wg.Add(1)
	go func() {
		defer wg.Done()
		if urlhausResult, err := m.manager.URLhaus.CheckDomain(ctx, domain); err == nil {
			mu.Lock()
			result["urlhaus"] = urlhausResult
			mu.Unlock()
		}
	}()

	// Certificate Transparency
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ctResult, err := m.manager.CT.QueryDomain(ctx, domain); err == nil {
			mu.Lock()
			result["cert_transparency"] = ctResult
			mu.Unlock()
		}
	}()

	wg.Wait()
	return result
}

// IsSuspiciousIP checks if an IP is suspicious based on multiple indicators
func (m *IntelModule) IsSuspiciousIP(ctx context.Context, ip string) (bool, map[string]interface{}) {
	indicators := make(map[string]interface{})
	suspicious := false

	// Check AbuseIPDB
	if m.manager.AbuseIPDB.IsConfigured() {
		if abuseResult, err := m.manager.AbuseIPDB.CheckIP(ctx, ip); err == nil {
			indicators["abuse_score"] = abuseResult.AbuseConfidenceScore
			indicators["is_tor"] = abuseResult.IsTor
			indicators["total_reports"] = abuseResult.TotalReports

			if abuseResult.AbuseConfidenceScore > 25 || abuseResult.IsTor {
				suspicious = true
			}
		}
	}

	// Check Shodan
	if shodanResult, err := m.manager.Shodan.LookupIP(ctx, ip); err == nil {
		indicators["shodan_vulns"] = len(shodanResult.Vulns)
		indicators["shodan_risk_score"] = shodanResult.RiskScore

		if len(shodanResult.Vulns) > 0 || shodanResult.RiskScore > 20 {
			suspicious = true
		}
	}

	indicators["is_suspicious"] = suspicious
	return suspicious, indicators
}

// IsMaliciousDomain checks if a domain is malicious based on multiple sources
func (m *IntelModule) IsMaliciousDomain(ctx context.Context, domain string) (bool, map[string]interface{}) {
	indicators := make(map[string]interface{})
	malicious := false

	// Check URLhaus
	if urlhausResult, err := m.manager.URLhaus.CheckDomain(ctx, domain); err == nil {
		indicators["urlhaus_status"] = urlhausResult.Status
		indicators["is_malicious"] = urlhausResult.IsMalicious
		indicators["threat_type"] = urlhausResult.Threat

		if urlhausResult.IsMalicious {
			malicious = true
		}
	}

	indicators["is_malicious"] = malicious
	return malicious, indicators
}

// ExtractIPsFromTarget extracts IP addresses from a target string
func (m *IntelModule) ExtractIPsFromTarget(target string) []string {
	ips := []string{}

	// IP regex pattern
	ipPattern := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	matches := ipPattern.FindAllString(target, -1)

	for _, match := range matches {
		if net.ParseIP(match) != nil {
			ips = append(ips, match)
		}
	}

	return ips
}

// ExtractDomainsFromTarget extracts domain names from a target string
func (m *IntelModule) ExtractDomainsFromTarget(target string) []string {
	domains := []string{}

	// Domain regex pattern
	domainPattern := regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}`)
	matches := domainPattern.FindAllString(target, -1)

	for _, match := range matches {
		if !strings.Contains(match, ".") {
			continue
		}
		domains = append(domains, strings.ToLower(match))
	}

	return domains
}

// GetCVEDetails retrieves detailed information about a specific CVE
func (m *IntelModule) GetCVEDetails(ctx context.Context, cveID string) (*utils.NVDResult, error) {
	return m.manager.NVD.GetCVE(ctx, cveID)
}

// GetKnownCVEsForSoftware returns known CVEs for a software name and version
func (m *IntelModule) GetKnownCVEsForSoftware(name, version string) []payloads.CVEEntry {
	return payloads.MatchCVEsForTechnology(name, version)
}

// IsKnownExploitedVulnerability checks if a CVE is in the KEV catalog
func (m *IntelModule) IsKnownExploitedVulnerability(cveID string) bool {
	return payloads.IsKEV(cveID)
}
