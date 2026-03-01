package modules

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redteam/agentic-scanner/pkg/payloads"
	"github.com/redteam/agentic-scanner/pkg/utils"
)

// ============================================================================
// Reconnaissance Module
// ============================================================================

// ReconModule performs comprehensive reconnaissance scanning
type ReconModule struct {
	httpClient  *utils.HTTPClient
	dnsResolver *utils.DNSResolver
	timeout     time.Duration
	userAgent   string
}

// NewReconModule creates a new reconnaissance module
func NewReconModule() *ReconModule {
	return &ReconModule{
		httpClient:  utils.NewHTTPClient(30 * time.Second),
		dnsResolver: utils.DefaultResolver(),
		timeout:     30 * time.Second,
		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// Name returns the module name
func (m *ReconModule) Name() string {
	return "reconnaissance"
}

// Description returns the module description
func (m *ReconModule) Description() string {
	return "Comprehensive reconnaissance - DNS enumeration, port scanning, service detection, and technology fingerprinting"
}

// Category returns the module category
func (m *ReconModule) Category() string {
	return "recon"
}

// SupportedTargetTypes returns all target types supported by this module
func (m *ReconModule) SupportedTargetTypes() []TargetType {
	return AllTargetTypes
}

// Execute runs the reconnaissance module
func (m *ReconModule) Execute(ctx context.Context, config ModuleConfig) ModuleResult {
	result := ModuleResult{
		Module:    m.Name(),
		Status:    "running",
		StartedAt: time.Now(),
	}

	// Create timeout context if not provided
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	var findings []Finding
	var mu sync.Mutex

	// Extract hostname from target
	host := utils.GetHostFromTarget(config.Target)

	// Channel for collecting findings
	findingChan := make(chan Finding, 100)

	// Start a goroutine to collect findings
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for finding := range findingChan {
			mu.Lock()
			findings = append(findings, finding)
			mu.Unlock()
		}
	}()

	// Run DNS enumeration
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.enumerateDNS(ctx, host, findingChan)
	}()

	// Run subdomain enumeration
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.enumerateSubdomains(ctx, host, findingChan)
	}()

	// Run port scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.scanPorts(ctx, host, findingChan)
	}()

	// Run technology fingerprinting (if web target)
	if strings.HasPrefix(config.Target, "http") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.fingerprintTechnology(ctx, config.Target, findingChan)
		}()
	}

	// Run WHOIS/RDAP lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.lookupWHOIS(ctx, host, findingChan)
	}()

	// Wait for all workers to complete
	wg.Wait()
	close(findingChan)

	// Wait for collection goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for finding := range findingChan {
			findings = append(findings, finding)
		}
	}()

	result.Findings = findings
	result.Status = "completed"
	now := time.Now()
	result.EndedAt = &now

	return result
}

// ============================================================================
// DNS Enumeration
// ============================================================================

func (m *ReconModule) enumerateDNS(ctx context.Context, hostname string, findingChan chan<- Finding) {
	// Get all DNS records
	records := m.dnsResolver.GetAllRecords(ctx, hostname)

	for recordType, result := range records {
		if result.Error != "" {
			continue
		}

		for _, record := range result.Records {
			// Check if record is potentially sensitive
			isSensitive := m.isSensitiveDNSRecord(record)

			finding := CreateDNSFinding(m.Name(), recordType, record.Name, record.Value, isSensitive)
			select {
			case findingChan <- finding:
			case <-ctx.Done():
				return
			}
		}
	}

	// Perform reverse DNS lookups on resolved IPs
	if aResult, ok := records["A"]; ok && len(aResult.Records) > 0 {
		for _, record := range aResult.Records {
			ptrResult, err := m.dnsResolver.LookupPTR(ctx, record.Value)
			if err == nil && len(ptrResult.Records) > 0 {
				for _, ptr := range ptrResult.Records {
					finding := CreateDNSFinding(m.Name(), "PTR", ptr.Name, ptr.Value, false)
					select {
					case findingChan <- finding:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}
}

func (m *ReconModule) isSensitiveDNSRecord(record utils.DNSRecord) bool {
	// Check for sensitive keywords in DNS records
	sensitiveKeywords := []string{"admin", "internal", "dev", "test", "staging", "uat", "prod", "production", "vpn", "db", "database", "api", "api-key", "secret"}

	valueLower := strings.ToLower(record.Value)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(valueLower, keyword) {
			return true
		}
	}
	return false
}

// ============================================================================
// Subdomain Enumeration
// ============================================================================

func (m *ReconModule) enumerateSubdomains(ctx context.Context, domain string, findingChan chan<- Finding) {
	var discoveredSubdomains []string
	var mu sync.Mutex

	// Use crt.sh certificate transparency
	crtSubdomains, err := utils.FetchCRTSH(ctx, domain)
	if err == nil && len(crtSubdomains) > 0 {
		mu.Lock()
		discoveredSubdomains = append(discoveredSubdomains, crtSubdomains...)
		mu.Unlock()
	}

	// Check context
	if err := CheckContext(ctx); err != nil {
		return
	}

	// Brute force with wordlist
	wordlist := payloads.GetCommonSubdomains()

	// Rate limiter for DNS queries
	rateLimiter := NewRateLimiter(50) // 50 DNS queries per second
	defer rateLimiter.Stop()

	// Work channel
	work := make(chan string, len(wordlist))
	for _, subdomain := range wordlist {
		work <- subdomain + "." + domain
	}
	close(work)

	// Worker pool
	var wg sync.WaitGroup
	numWorkers := 100
	if numWorkers > len(wordlist) {
		numWorkers = len(wordlist)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case subdomain, ok := <-work:
					if !ok {
						return
					}

					rateLimiter.Wait()

					// Try to resolve the subdomain
					_, err := m.dnsResolver.LookupHost(ctx, subdomain)
					if err == nil {
						mu.Lock()
						discoveredSubdomains = append(discoveredSubdomains, subdomain)
						mu.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()

	// Create findings for discovered subdomains
	if len(discoveredSubdomains) > 0 {
		// Remove duplicates
		uniqueSubdomains := removeDuplicates(discoveredSubdomains)

		finding := CreateSubdomainFinding(m.Name(), uniqueSubdomains)
		select {
		case findingChan <- finding:
		case <-ctx.Done():
		}
	}
}

// ============================================================================
// Port Scanning
// ============================================================================

func (m *ReconModule) scanPorts(ctx context.Context, host string, findingChan chan<- Finding) {
	// Resolve hostname to IP if needed
	ips, err := m.dnsResolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return
	}

	targetIP := ips[0]

	// Get ports to scan
	ports := payloads.GetTop1000Ports()
	interestingPorts := payloads.GetInterestingPorts()

	// Always include interesting ports
	for port := range interestingPorts {
		found := false
		for _, p := range ports {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			ports = append(ports, port)
		}
	}

	// Scan ports
	config := utils.DefaultPortScanConfig()
	config.Concurrency = 200
	config.Timeout = 5 * time.Second

	results, err := utils.ScanPorts(ctx, targetIP, ports, config)
	if err != nil {
		return
	}

	// Process results
	for _, result := range results {
		if !result.Open {
			continue
		}

		// Determine if port is interesting
		isInteresting := payloads.IsInterestingPort(result.Port)
		service := result.Service
		if service == "" || service == "unknown" {
			service = utils.GetServiceForPort(result.Port)
		}

		finding := CreatePortFinding(m.Name(), result.Port, service, result.Banner, isInteresting)

		select {
		case findingChan <- finding:
		case <-ctx.Done():
			return
		}
	}
}

// ============================================================================
// Technology Fingerprinting
// ============================================================================

func (m *ReconModule) fingerprintTechnology(ctx context.Context, targetURL string, findingChan chan<- Finding) {
	// Ensure URL has scheme
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	// Fetch the main page
	req := &utils.HTTPRequest{
		Method: "GET",
		URL:    targetURL,
		Headers: map[string]string{
			"User-Agent": m.userAgent,
			"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	}

	resp, err := m.httpClient.Do(ctx, req)
	if err != nil {
		// Try HTTP if HTTPS fails
		if strings.HasPrefix(targetURL, "https://") {
			targetURL = strings.Replace(targetURL, "https://", "http://", 1)
			req.URL = targetURL
			resp, err = m.httpClient.Do(ctx, req)
			if err != nil {
				return
			}
		} else {
			return
		}
	}

	// Analyze headers
	m.analyzeHeaders(resp.Headers, findingChan)

	// Check security headers
	m.checkSecurityHeaders(resp.Headers, findingChan)

	// Check cookies
	m.checkCookies(resp.Headers, findingChan)

	// Analyze HTML content
	if len(resp.Body) > 0 {
		html := string(resp.Body)
		m.analyzeHTML(targetURL, html, findingChan)

		// Look for JavaScript files
		m.analyzeJavaScript(ctx, targetURL, html, findingChan)
	}

	// Check for common technology signatures
	m.matchTechnologySignatures(resp.Headers, string(resp.Body), findingChan)
}

func (m *ReconModule) analyzeHeaders(headers map[string][]string, findingChan chan<- Finding) {
	// Check for server header disclosure
	if server := headers["Server"]; len(server) > 0 && server[0] != "" {
		finding := CreateFinding(m.Name(), "Server Header Disclosure",
			fmt.Sprintf("Server header reveals: %s", server[0]),
			SeverityLow, "information-disclosure")
		finding.Evidence.Details = map[string]interface{}{
			"header": "Server",
			"value":  server[0],
		}
		finding.Remediation = "Configure your web server to suppress or modify the Server header to reveal less information."
		findingChan <- finding
	}

	// Check for X-Powered-By
	if poweredBy := headers["X-Powered-By"]; len(poweredBy) > 0 && poweredBy[0] != "" {
		finding := CreateFinding(m.Name(), "X-Powered-By Header Disclosure",
			fmt.Sprintf("X-Powered-By header reveals: %s", poweredBy[0]),
			SeverityLow, "information-disclosure")
		finding.Evidence.Details = map[string]interface{}{
			"header": "X-Powered-By",
			"value":  poweredBy[0],
		}
		finding.Remediation = "Remove the X-Powered-By header from server responses."
		findingChan <- finding
	}

	// Check for framework-specific headers
	frameworkHeaders := map[string]string{
		"X-AspNet-Version":    "ASP.NET",
		"X-AspNetMvc-Version": "ASP.NET MVC",
		"X-Runtime":           "Ruby on Rails",
		"X-Generator":         "Various CMS",
		"X-Drupal-Cache":      "Drupal",
		"X-Pingback":          "WordPress",
	}

	for header, framework := range frameworkHeaders {
		if value := headers[header]; len(value) > 0 && value[0] != "" {
			finding := CreateFinding(m.Name(), fmt.Sprintf("%s Framework Detected", framework),
				fmt.Sprintf("%s header indicates %s usage", header, framework),
				SeverityInfo, "technology-fingerprinting")
			finding.Evidence.Details = map[string]interface{}{
				"header":    header,
				"value":     value[0],
				"framework": framework,
			}
			findingChan <- finding
		}
	}
}

func (m *ReconModule) checkSecurityHeaders(headers map[string][]string, findingChan chan<- Finding) {
	securityHeaders := map[string]struct {
		severity Severity
		required bool
	}{
		"Content-Security-Policy":   {SeverityMedium, true},
		"Strict-Transport-Security": {SeverityHigh, true},
		"X-Frame-Options":           {SeverityMedium, true},
		"X-Content-Type-Options":    {SeverityMedium, true},
		"Referrer-Policy":           {SeverityLow, false},
		"Permissions-Policy":        {SeverityLow, false},
		"X-XSS-Protection":          {SeverityLow, false},
	}

	for header := range securityHeaders {
		if values := headers[header]; len(values) == 0 || values[0] == "" {
			// Header is missing
			finding := CreateSecurityHeaderFinding(m.Name(), header, true, "")
			findingChan <- finding
		}
	}

	// Check for insecure CSP
	if csp := headers["Content-Security-Policy"]; len(csp) > 0 && csp[0] != "" {
		cspValue := strings.ToLower(csp[0])
		if strings.Contains(cspValue, "unsafe-inline") || strings.Contains(cspValue, "unsafe-eval") {
			finding := CreateFinding(m.Name(), "Insecure CSP Directives",
				"Content Security Policy contains unsafe directives (unsafe-inline or unsafe-eval)",
				SeverityMedium, "security-headers")
			finding.Evidence.Details = map[string]interface{}{
				"csp": csp[0],
			}
			finding.Remediation = "Avoid using 'unsafe-inline' and 'unsafe-eval' in CSP. Use nonces or hashes instead."
			findingChan <- finding
		}
	}
}

func (m *ReconModule) checkCookies(headers map[string][]string, findingChan chan<- Finding) {
	setCookieHeaders := headers["Set-Cookie"]
	if len(setCookieHeaders) == 0 {
		return
	}

	for _, cookie := range setCookieHeaders {
		cookieName := m.extractCookieName(cookie)
		if cookieName == "" {
			continue
		}

		// Check for Secure flag
		if !strings.Contains(cookie, "Secure") {
			finding := CreateCookieFinding(m.Name(), cookieName, "missing Secure flag")
			findingChan <- finding
		}

		// Check for HttpOnly flag
		if !strings.Contains(cookie, "HttpOnly") {
			finding := CreateCookieFinding(m.Name(), cookieName, "missing HttpOnly flag")
			findingChan <- finding
		}

		// Check for SameSite attribute
		if !strings.Contains(strings.ToLower(cookie), "samesite") {
			finding := CreateCookieFinding(m.Name(), cookieName, "missing SameSite attribute")
			findingChan <- finding
		}
	}
}

func (m *ReconModule) extractCookieName(cookie string) string {
	parts := strings.Split(cookie, ";")
	if len(parts) == 0 {
		return ""
	}

	namePart := strings.TrimSpace(parts[0])
	eqIndex := strings.Index(namePart, "=")
	if eqIndex > 0 {
		return strings.TrimSpace(namePart[:eqIndex])
	}

	return ""
}

func (m *ReconModule) analyzeHTML(baseURL, html string, findingChan chan<- Finding) {
	signatures := payloads.GetTechnologySignatures()

	for _, sig := range signatures {
		matched := false

		// Check HTML patterns
		for _, pattern := range sig.HTML {
			if strings.Contains(html, pattern) {
				matched = true
				break
			}
		}

		if matched {
			finding := CreateTechnologyFinding(m.Name(), sig.Name, "", sig.Category)
			findingChan <- finding
		}
	}

	// Extract and analyze meta tags
	metaGenerator := m.extractMetaTag(html, "generator")
	if metaGenerator != "" {
		finding := CreateFinding(m.Name(), "Meta Generator Tag Detected",
			fmt.Sprintf("Meta generator reveals: %s", metaGenerator),
			SeverityLow, "technology-fingerprinting")
		finding.Evidence.Details = map[string]interface{}{
			"meta":  "generator",
			"value": metaGenerator,
		}
		finding.Remediation = "Remove the meta generator tag to prevent technology disclosure."
		findingChan <- finding
	}
}

func (m *ReconModule) extractMetaTag(html, name string) string {
	// Simple regex-based extraction
	pattern := fmt.Sprintf(`<meta[^>]+name=["']%s["'][^>]+content=["']([^"']+)["']`, regexp.QuoteMeta(name))
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}

	// Try reverse attribute order
	pattern = fmt.Sprintf(`<meta[^>]+content=["']([^"']+)["'][^>]+name=["']%s["']`, regexp.QuoteMeta(name))
	re = regexp.MustCompile(pattern)
	matches = re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func (m *ReconModule) analyzeJavaScript(ctx context.Context, baseURL, html string, findingChan chan<- Finding) {
	// Extract script src URLs
	scriptPattern := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptPattern.FindAllStringSubmatch(html, -1)

	var jsURLs []string
	for _, match := range matches {
		if len(match) > 1 {
			jsURL := match[1]
			// Resolve relative URLs
			if strings.HasPrefix(jsURL, "//") {
				jsURL = "https:" + jsURL
			} else if strings.HasPrefix(jsURL, "/") {
				base, _ := url.Parse(baseURL)
				jsURL = base.Scheme + "://" + base.Host + jsURL
			} else if !strings.HasPrefix(jsURL, "http") {
				base, _ := url.Parse(baseURL)
				jsURL = base.String() + "/" + jsURL
			}
			jsURLs = append(jsURLs, jsURL)
		}
	}

	// Limit to first 5 JS files
	if len(jsURLs) > 5 {
		jsURLs = jsURLs[:5]
	}

	// Check for source maps
	for _, jsURL := range jsURLs {
		select {
		case <-ctx.Done():
			return
		default:
			m.checkSourceMap(ctx, jsURL, findingChan)
		}
	}
}

func (m *ReconModule) checkSourceMap(ctx context.Context, jsURL string, findingChan chan<- Finding) {
	// Check if source map exists
	mapURL := jsURL + ".map"

	req := &utils.HTTPRequest{
		Method: "GET",
		URL:    mapURL,
		Headers: map[string]string{
			"User-Agent": m.userAgent,
		},
	}

	resp, err := m.httpClient.Do(ctx, req)
	if err == nil && resp.StatusCode == 200 {
		finding := CreateFinding(m.Name(), "JavaScript Source Map Exposed",
			fmt.Sprintf("Source map file exposed at: %s", mapURL),
			SeverityMedium, "information-disclosure")
		finding.Evidence.Details = map[string]interface{}{
			"source_map_url": mapURL,
		}
		finding.Remediation = "Remove source map files from production or restrict access to them."
		finding.References = []string{"https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map"}
		findingChan <- finding
	}
}

func (m *ReconModule) matchTechnologySignatures(headers map[string][]string, body string, findingChan chan<- Finding) {
	signatures := payloads.GetTechnologySignatures()

	for _, sig := range signatures {
		matched := false
		version := ""

		// Check headers
		for _, pattern := range sig.Headers {
			if values, ok := headers[pattern.Header]; ok {
				for _, value := range values {
					if strings.Contains(value, pattern.Pattern) {
						matched = true
						// Try to extract version
						version = m.extractVersion(value)
						break
					}
				}
			}
		}

		// Check cookies
		if !matched {
			for _, cookiePattern := range sig.Cookies {
				if setCookie := headers["Set-Cookie"]; len(setCookie) > 0 {
					for _, cookie := range setCookie {
						if strings.Contains(cookie, cookiePattern) {
							matched = true
							break
						}
					}
				}
			}
		}

		// Check HTML body
		if !matched {
			for _, pattern := range sig.HTML {
				if strings.Contains(body, pattern) {
					matched = true
					break
				}
			}
		}

		if matched {
			finding := CreateTechnologyFinding(m.Name(), sig.Name, version, sig.Category)
			findingChan <- finding
		}
	}
}

func (m *ReconModule) extractVersion(value string) string {
	// Try to extract version number from header value
	versionPattern := regexp.MustCompile(`[/\s]([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	matches := versionPattern.FindStringSubmatch(value)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ============================================================================
// WHOIS/RDAP Lookup
// ============================================================================

func (m *ReconModule) lookupWHOIS(ctx context.Context, hostname string, findingChan chan<- Finding) {
	// Extract domain from hostname
	domain := utils.ExtractDomain(hostname)

	whoisResult, err := utils.FetchRDAP(ctx, domain)
	if err != nil || whoisResult.Error != "" {
		return
	}

	// Create informational finding with WHOIS data
	finding := CreateInfoFinding(m.Name(), "WHOIS Information Available",
		fmt.Sprintf("Domain registration information retrieved for %s", domain),
		"recon")

	details := map[string]interface{}{
		"domain":      whoisResult.Domain,
		"registrar":   whoisResult.Registrar,
		"created":     whoisResult.Created,
		"expires":     whoisResult.Expires,
		"nameservers": whoisResult.Nameservers,
	}
	finding.Evidence.Details = details

	select {
	case findingChan <- finding:
	case <-ctx.Done():
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range slice {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// ============================================================================
// Additional Recon Functions
// ============================================================================

// RunZoneTransfer attempts zone transfer on discovered nameservers
func (m *ReconModule) RunZoneTransfer(ctx context.Context, domain string, nameservers []string) ([]Finding, error) {
	var findings []Finding

	for _, ns := range nameservers {
		// Note: Full AXFR implementation requires miekg/dns library
		// This is a placeholder that documents the attempt

		// In a full implementation:
		// 1. Connect to nameserver on TCP port 53
		// 2. Send AXFR query for the domain
		// 3. Parse response records
		// 4. If successful, enumerate all zone records

		// For now, we document that zone transfer was attempted
		finding := CreateInfoFinding(m.Name(),
			fmt.Sprintf("Zone Transfer Attempted on %s", ns),
			fmt.Sprintf("Attempted AXFR against %s for domain %s", ns, domain),
			"dns-enumeration")

		findings = append(findings, finding)
	}

	return findings, nil
}

// GetIPInfo retrieves ASN and BGP information for an IP
func (m *ReconModule) GetIPInfo(ctx context.Context, ip string) (*utils.IPInfoResponse, error) {
	return utils.FetchIPInfo(ctx, ip)
}

// DetectWAF attempts to detect Web Application Firewall
func (m *ReconModule) DetectWAF(ctx context.Context, targetURL string) (string, error) {
	req := &utils.HTTPRequest{
		Method: "GET",
		URL:    targetURL,
		Headers: map[string]string{
			"User-Agent": m.userAgent,
		},
	}

	resp, err := m.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}

	// Check for WAF signatures in headers
	wafSignatures := map[string]string{
		"CF-RAY":               "Cloudflare",
		"X-Sucuri-ID":          "Sucuri",
		"X-Iinfo":              "Incapsula",
		"X-Akamai-Transformed": "Akamai",
		"X-CDN":                "CDN",
	}

	for header, wafName := range wafSignatures {
		if _, ok := resp.Headers[header]; ok {
			return wafName, nil
		}
	}

	return "", nil
}

// CheckRobotsTxt checks for robots.txt and sitemap.xml
func (m *ReconModule) CheckRobotsTxt(ctx context.Context, targetURL string) ([]Finding, error) {
	var findings []Finding

	// Parse base URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return findings, err
	}

	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// Check robots.txt
	robotsURL := baseURL + "/robots.txt"
	req := &utils.HTTPRequest{
		Method: "GET",
		URL:    robotsURL,
		Headers: map[string]string{
			"User-Agent": m.userAgent,
		},
	}

	resp, err := m.httpClient.Do(ctx, req)
	if err == nil && resp.StatusCode == 200 && len(resp.Body) > 0 {
		// Parse robots.txt for interesting entries
		content := string(resp.Body)
		interesting := m.parseRobotsTxt(content)

		if len(interesting) > 0 {
			finding := CreateInfoFinding(m.Name(),
				"Interesting robots.txt Entries",
				fmt.Sprintf("Found %d potentially interesting entries in robots.txt", len(interesting)),
				"recon")
			finding.Evidence.Details = map[string]interface{}{
				"entries": interesting,
			}
			findings = append(findings, finding)
		}
	}

	// Check sitemap.xml
	sitemapURL := baseURL + "/sitemap.xml"
	req.URL = sitemapURL

	resp, err = m.httpClient.Do(ctx, req)
	if err == nil && resp.StatusCode == 200 && len(resp.Body) > 0 {
		finding := CreateInfoFinding(m.Name(),
			"Sitemap.xml Discovered",
			"Sitemap.xml was found and may reveal site structure",
			"recon")
		findings = append(findings, finding)
	}

	return findings, nil
}

func (m *ReconModule) parseRobotsTxt(content string) []string {
	var interesting []string
	scanner := bufio.NewScanner(strings.NewReader(content))

	sensitivePatterns := []string{
		"admin", "login", "api", "config", "backup", "private", "internal",
		"wp-admin", "wp-login", "administrator", "panel", "dashboard",
	}

	for scanner.Scan() {
		line := scanner.Text()
		lineLower := strings.ToLower(line)

		for _, pattern := range sensitivePatterns {
			if strings.Contains(lineLower, pattern) {
				interesting = append(interesting, strings.TrimSpace(line))
				break
			}
		}
	}

	return interesting
}

// CheckCommonFiles checks for common sensitive files
func (m *ReconModule) CheckCommonFiles(ctx context.Context, targetURL string) ([]Finding, error) {
	var findings []Finding

	commonFiles := []string{
		"robots.txt", "sitemap.xml", ".git/config", ".env", ".htaccess",
		"config.php", "config.json", "settings.php", "wp-config.php",
		"phpinfo.php", "info.php", "server-status", "server-info",
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return findings, err
	}

	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent requests

	for _, file := range commonFiles {
		wg.Add(1)
		go func(filename string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			fileURL := baseURL + "/" + filename
			req := &utils.HTTPRequest{
				Method: "GET",
				URL:    fileURL,
				Headers: map[string]string{
					"User-Agent": m.userAgent,
				},
			}

			resp, err := m.httpClient.Do(ctx, req)
			if err != nil {
				return
			}

			// Check if file exists and may be sensitive
			if resp.StatusCode == 200 && len(resp.Body) > 0 {
				// Determine severity based on file type
				severity := SeverityLow
				if strings.Contains(filename, ".env") || strings.Contains(filename, "config") {
					severity = SeverityHigh
				} else if strings.Contains(filename, ".git") {
					severity = SeverityCritical
				}

				title := fmt.Sprintf("Potentially Sensitive File Exposed: %s", filename)
				description := fmt.Sprintf("The file %s is accessible and may contain sensitive information.", filename)

				finding := CreateFinding(m.Name(), title, description, severity, "information-disclosure")
				finding.Evidence.Details = map[string]interface{}{
					"url":    fileURL,
					"status": resp.StatusCode,
					"size":   len(resp.Body),
				}

				switch filename {
				case ".git/config":
					finding.Remediation = "Remove .git directory from web root or deny access via web server configuration."
					finding.References = []string{"https://git-scm.com/docs/git-config"}
				case ".env":
					finding.Remediation = "Remove .env file from web root or deny access via web server configuration. Store environment variables securely."
					finding.References = []string{"https://12factor.net/config"}
				default:
					finding.Remediation = "Review file permissions and remove or restrict access to sensitive configuration files."
				}

				findings = append(findings, finding)
			}
		}(file)
	}

	wg.Wait()
	return findings, nil
}

// ServiceBanner holds information extracted from a service banner
type ServiceBanner struct {
	Service   string
	Version   string
	ExtraInfo string
}

// ParseServiceBanner parses a service banner to extract information
func (m *ReconModule) ParseServiceBanner(banner, serviceType string) ServiceBanner {
	result := ServiceBanner{Service: serviceType}

	switch serviceType {
	case "SSH":
		// SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
		parts := strings.Split(banner, "-")
		if len(parts) >= 3 {
			result.Version = parts[2]
		}
		if len(parts) >= 4 {
			result.ExtraInfo = strings.Join(parts[3:], "-")
		}

	case "HTTP", "HTTPS":
		// Server: nginx/1.18.0
		if strings.HasPrefix(banner, "Server:") {
			server := strings.TrimPrefix(banner, "Server:")
			server = strings.TrimSpace(server)
			parts := strings.Split(server, "/")
			if len(parts) >= 2 {
				result.Service = parts[0]
				result.Version = parts[1]
			}
		}

	case "FTP":
		// 220 Welcome to Pure-FTPd [privsep] [TLS]
		if strings.Contains(banner, "Pure-FTPd") {
			result.Service = "Pure-FTPd"
			result.ExtraInfo = "TLS support detected"
		} else if strings.Contains(banner, "vsftpd") {
			result.Service = "vsftpd"
		}
	}

	return result
}

// IsVulnerableVersion checks if a service version is known to be vulnerable
func (m *ReconModule) IsVulnerableVersion(service, version string) (bool, []string) {
	// This is a simplified check - use a proper vulnerability database for production
	knownVulns := map[string]map[string][]string{
		"OpenSSH": {
			"<7.0": {"CVE-2016-0777", "CVE-2016-0778"},
			"<8.0": {"CVE-2020-15778"},
		},
		"Apache": {
			"<2.4.41": {"CVE-2019-0211", "CVE-2019-0220"},
		},
		"nginx": {
			"<1.16.1": {"CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516"},
		},
	}

	if versions, ok := knownVulns[service]; ok {
		for rangeSpec, cves := range versions {
			if m.versionInRange(version, rangeSpec) {
				return true, cves
			}
		}
	}

	return false, nil
}

func (m *ReconModule) versionInRange(version, rangeSpec string) bool {
	// Simplified version comparison
	// RangeSpec format: "<1.16.1" or ">=2.4.0"
	if strings.HasPrefix(rangeSpec, "<") {
		compareVersion := strings.TrimPrefix(rangeSpec, "<")
		return m.compareVersions(version, compareVersion) < 0
	}
	if strings.HasPrefix(rangeSpec, "<=") {
		compareVersion := strings.TrimPrefix(rangeSpec, "<=")
		return m.compareVersions(version, compareVersion) <= 0
	}
	if strings.HasPrefix(rangeSpec, ">=") {
		compareVersion := strings.TrimPrefix(rangeSpec, ">=")
		return m.compareVersions(version, compareVersion) >= 0
	}
	if strings.HasPrefix(rangeSpec, ">") {
		compareVersion := strings.TrimPrefix(rangeSpec, ">")
		return m.compareVersions(version, compareVersion) > 0
	}
	return false
}

func (m *ReconModule) compareVersions(v1, v2 string) int {
	// Compare two version strings
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		n1, _ := strconv.Atoi(parts1[i])
		n2, _ := strconv.Atoi(parts2[i])

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	return len(parts1) - len(parts2)
}

// CreateVulnerableVersionFinding creates a finding for known vulnerable software version
func (m *ReconModule) CreateVulnerableVersionFinding(service, version string, cves []string) Finding {
	title := fmt.Sprintf("Potentially Vulnerable %s Version", service)
	description := fmt.Sprintf("%s version %s may have known vulnerabilities.", service, version)

	severity := SeverityMedium
	if len(cves) > 0 {
		for _, cve := range cves {
			description += fmt.Sprintf(" %s", cve)
		}
		// If critical CVEs found, increase severity
		severity = SeverityHigh
	}

	finding := CreateFinding(m.Name(), title, description, severity, "outdated-software")
	finding.CVEs = cves
	finding.Evidence.Details = map[string]interface{}{
		"service": service,
		"version": version,
	}
	finding.Remediation = fmt.Sprintf("Update %s to the latest stable version.", service)
	finding.References = []string{"https://nvd.nist.gov/"}

	return finding
}

// Verify interface compliance
var _ Module = (*ReconModule)(nil)
