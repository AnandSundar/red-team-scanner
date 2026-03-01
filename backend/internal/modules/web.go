package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redteam/agentic-scanner/pkg/payloads"
	"github.com/redteam/agentic-scanner/pkg/utils"
)

// WebModule performs comprehensive web application security testing
type WebModule struct {
	httpClient *utils.SecurityHTTPClient
	wordlist   []string
	timeout    time.Duration
}

// NewWebModule creates a new WebModule instance
func NewWebModule() *WebModule {
	return &WebModule{
		timeout: 60 * time.Second,
	}
}

// Name returns the module name
func (m *WebModule) Name() string {
	return "web"
}

// Description returns the module description
func (m *WebModule) Description() string {
	return "Web Application Security Testing - Content discovery, injection tests, CORS, HTTP methods, and TLS analysis"
}

// Category returns the module category
func (m *WebModule) Category() string {
	return "web_application"
}

// SupportedTargetTypes returns the target types this module supports
func (m *WebModule) SupportedTargetTypes() []TargetType {
	return []TargetType{TargetTypeWeb, TargetTypeAPI}
}

// Execute runs the web security module
func (m *WebModule) Execute(ctx context.Context, config ModuleConfig) ModuleResult {
	result := ModuleResult{
		Module:    m.Name(),
		Status:    "running",
		StartedAt: time.Now(),
	}

	// Create HTTP client with timeout
	m.httpClient = utils.NewSecurityHTTPClient(10*time.Second, 10)
	m.httpClient.SetRateLimit(10) // 10 requests per second
	defer m.httpClient.Stop()

	// Create context with 60 second timeout
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	findings := []Finding{}
	findingsMu := sync.Mutex{}

	// Create error channel for goroutines
	errChan := make(chan error, 1)
	findingChan := make(chan Finding, 100)

	// Collect findings from channel
	go func() {
		for finding := range findingChan {
			findingsMu.Lock()
			findings = append(findings, finding)
			findingsMu.Unlock()
		}
	}()

	// Run tests in parallel
	var wg sync.WaitGroup

	// 1. Content Discovery - Sensitive Paths (ALWAYS run)
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testSensitivePaths(ctx, config.Target, findingChan)
	}()

	// 2. Content Discovery - Directory Brute-Force
	if config.Depth >= 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.testDirectoryBruteForce(ctx, config.Target, config.Depth, findingChan)
		}()
	}

	// 3. Injection Testing
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testInjectionVulnerabilities(ctx, config.Target, findingChan)
	}()

	// 4. CORS Testing
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testCORS(ctx, config.Target, findingChan)
	}()

	// 5. HTTP Method Testing
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testHTTPMethods(ctx, config.Target, findingChan)
	}()

	// 6. TLS/SSL Analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testTLS(ctx, config.Target, findingChan)
	}()

	// 7. Security Headers
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testSecurityHeaders(ctx, config.Target, findingChan)
	}()

	// Wait for all tests to complete or context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(findingChan)
		close(done)
	}()

	select {
	case <-done:
		// All tests completed
	case <-ctx.Done():
		// Context cancelled or timeout
		result.Error = ctx.Err().Error()
	case err := <-errChan:
		if err != nil {
			result.Error = err.Error()
		}
	}

	result.Findings = findings
	result.Status = "completed"
	now := time.Now()
	result.EndedAt = &now

	return result
}

// testSensitivePaths tests for sensitive file exposures
func (m *WebModule) testSensitivePaths(ctx context.Context, target string, findingChan chan<- Finding) {
	for _, path := range payloads.SensitivePaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		testURL := target + path
		resp, err := m.httpClient.Get(testURL, nil)
		if err != nil {
			continue
		}

		// Check for interesting status codes
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			// Check if it's not a 404 page disguised as 200
			bodyStr := string(resp.Body)
			if !strings.Contains(strings.ToLower(bodyStr), "not found") &&
				!strings.Contains(strings.ToLower(bodyStr), "error") &&
				len(resp.Body) > 10 {
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
				}
				finding := CreateSensitiveFileFinding(m.Name(), testURL, path, resp.StatusCode, evidence)
				findingChan <- finding
			}
		} else if resp.StatusCode == 403 {
			// Forbidden but exists - still worth noting
			evidence := FindingEvidence{
				Request:  resp.RawRequest,
				Response: resp.RawResponse,
				Details: map[string]interface{}{
					"note": "File exists but access is forbidden",
				},
			}
			finding := CreateDirectoryFinding(m.Name(), testURL, path, resp.StatusCode)
			finding.Evidence = evidence
			finding.Severity = SeverityInfo
			findingChan <- finding
		}
	}
}

// testDirectoryBruteForce performs directory brute-forcing
func (m *WebModule) testDirectoryBruteForce(ctx context.Context, target string, depth int, findingChan chan<- Finding) {
	// Determine wordlist size based on depth
	var wordlist []string
	if depth >= 3 {
		// Full scope - use top 20000 paths
		wordlist = payloads.CommonDirectories
	} else {
		// Standard scope - use top 5000 paths or all if less
		wordlist = payloads.CommonDirectories
	}

	// Limit concurrent requests
	semaphore := make(chan struct{}, 50)
	var wg sync.WaitGroup

	for _, dir := range wordlist {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(directory string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			testURL := target + "/" + directory
			resp, err := m.httpClient.Get(testURL, nil)
			if err != nil {
				return
			}

			// Flag interesting responses
			if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 ||
				resp.StatusCode == 403 || resp.StatusCode == 500 {
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
				}
				finding := CreateDirectoryFinding(m.Name(), testURL, "/"+directory, resp.StatusCode)
				finding.Evidence = evidence
				findingChan <- finding
			}
		}(dir)
	}

	wg.Wait()
}

// testInjectionVulnerabilities tests for XSS, SQLi, Open Redirect, and Path Traversal
func (m *WebModule) testInjectionVulnerabilities(ctx context.Context, target string, findingChan chan<- Finding) {
	// Parse URL to get base and parameters
	u, err := url.Parse(target)
	if err != nil {
		return
	}

	// Get existing parameters
	params := u.Query()

	// Test XSS on each parameter
	for param := range params {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for _, payload := range payloads.XSSPayloads {
			testURL, _ := utils.BuildURLWithParam(target, param, payload)
			resp, err := m.httpClient.Get(testURL, nil)
			if err != nil {
				continue
			}

			// Check for WAF block
			if utils.IsWAFBlocked(resp) {
				continue
			}

			// Check if payload is reflected
			detector := utils.NewXSSDetector()
			if detector.Detect(payload, resp.Body) {
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
					Payload:  payload,
					URL:      testURL,
				}
				finding := CreateXSSFinding(m.Name(), testURL, param, payload, evidence)
				findingChan <- finding
				break // Found XSS for this parameter, move to next
			}
		}
	}

	// Test SQL Injection on each parameter
	for param := range params {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for _, payload := range payloads.SQLiErrorPayloads {
			testURL, _ := utils.BuildURLWithParam(target, param, payload)
			resp, err := m.httpClient.Get(testURL, nil)
			if err != nil {
				continue
			}

			// Check for SQL errors
			detector := utils.NewSQLiDetector()
			if found, errorMsg := detector.Detect(resp.Body); found {
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
					Payload:  payload,
					URL:      testURL,
					Snippet:  errorMsg,
				}
				finding := CreateSQLiFinding(m.Name(), testURL, param, errorMsg, evidence)
				findingChan <- finding
				break // Found SQLi for this parameter, move to next
			}
		}
	}

	// Test Open Redirect
	for _, param := range payloads.OpenRedirectParams {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for _, payload := range payloads.OpenRedirectPayloads {
			testURL, _ := utils.BuildURLWithParam(target, param, payload)
			resp, err := m.httpClient.Get(testURL, nil)
			if err != nil {
				continue
			}

			// Check for redirect to external domain
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Headers.Get("Location")
				if strings.Contains(location, "evil.com") ||
					strings.HasPrefix(location, "//") ||
					strings.HasPrefix(location, "http://evil.com") ||
					strings.HasPrefix(location, "https://evil.com") {
					evidence := FindingEvidence{
						Request:  resp.RawRequest,
						Response: resp.RawResponse,
						Payload:  payload,
						URL:      testURL,
					}
					finding := CreateOpenRedirectFinding(m.Name(), testURL, param, payload, evidence)
					findingChan <- finding
					break
				}
			}
		}
	}

	// Test Path Traversal on common file parameters
	fileParams := []string{"file", "path", "filename", "dir", "directory", "page", "include", "load"}
	for _, param := range fileParams {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for _, payload := range payloads.PathTraversalPayloads {
			testURL, _ := utils.BuildURLWithParam(target, param, payload)
			resp, err := m.httpClient.Get(testURL, nil)
			if err != nil {
				continue
			}

			// Check for signs of successful traversal
			bodyStr := string(resp.Body)
			if strings.Contains(bodyStr, "root:") ||
				strings.Contains(bodyStr, "[extensions]") || // win.ini
				strings.Contains(bodyStr, "for 16-bit app") { // win.ini
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
					Payload:  payload,
					URL:      testURL,
				}
				finding := CreatePathTraversalFinding(m.Name(), testURL, param, payload, evidence)
				findingChan <- finding
				break
			}
		}
	}
}

// testCORS tests for CORS misconfigurations
func (m *WebModule) testCORS(ctx context.Context, target string, findingChan chan<- Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	tester := utils.NewCORSTester(m.httpClient)
	result, err := tester.Test(target)
	if err != nil {
		return
	}

	if result.Vulnerable {
		evidence := FindingEvidence{
			URL:     target,
			Snippet: result.Evidence,
			Details: map[string]interface{}{
				"allow_origin":      result.AllowOrigin,
				"allow_credentials": result.AllowCredentials,
				"allow_methods":     result.AllowMethods,
				"allow_headers":     result.AllowHeaders,
			},
		}
		finding := CreateCORSFinding(m.Name(), target, result.Severity, result.Evidence, result.AllowOrigin, result.AllowCredentials)
		finding.Evidence = evidence
		findingChan <- finding
	}
}

// testHTTPMethods tests for dangerous HTTP method support
func (m *WebModule) testHTTPMethods(ctx context.Context, target string, findingChan chan<- Finding) {
	// OPTIONS request to see allowed methods
	resp, err := m.httpClient.Request("OPTIONS", target, nil, nil)
	if err != nil {
		return
	}

	allowHeader := resp.Headers.Get("Allow")
	if allowHeader != "" {
		methods := strings.Split(allowHeader, ",")
		for _, method := range methods {
			method = strings.TrimSpace(strings.ToUpper(method))
			dangerous := method == "PUT" || method == "DELETE" || method == "TRACE" || method == "CONNECT" || method == "PATCH"
			finding := CreateHTTPMethodFinding(m.Name(), target, method, resp.StatusCode, dangerous)
			findingChan <- finding
		}
	}

	// Test PUT method
	select {
	case <-ctx.Done():
		return
	default:
	}

	testPath := target + "/test-" + fmt.Sprintf("%d", time.Now().Unix())
	putResp, err := m.httpClient.Request("PUT", testPath, map[string]string{"Content-Type": "text/plain"}, []byte("test"))
	if err == nil && (putResp.StatusCode == 200 || putResp.StatusCode == 201 || putResp.StatusCode == 204) {
		finding := CreateHTTPMethodFinding(m.Name(), target, "PUT", putResp.StatusCode, true)
		finding.Evidence = FindingEvidence{
			Request:  putResp.RawRequest,
			Response: putResp.RawResponse,
		}
		findingChan <- finding
	}

	// Test TRACE method (XST)
	select {
	case <-ctx.Done():
		return
	default:
	}

	traceResp, err := m.httpClient.Request("TRACE", target, nil, nil)
	if err == nil && traceResp.StatusCode == 200 {
		// Check if response echoes our request (indicating TRACE is enabled)
		bodyStr := string(traceResp.Body)
		if strings.Contains(strings.ToUpper(bodyStr), "TRACE") {
			finding := CreateHTTPMethodFinding(m.Name(), target, "TRACE", traceResp.StatusCode, true)
			finding.Evidence = FindingEvidence{
				Request:  traceResp.RawRequest,
				Response: traceResp.RawResponse,
			}
			findingChan <- finding
		}
	}
}

// testTLS tests TLS/SSL configuration
func (m *WebModule) testTLS(ctx context.Context, target string, findingChan chan<- Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	u, err := url.Parse(target)
	if err != nil {
		return
	}

	if u.Scheme != "https" {
		return
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Test TLS versions
	tlsVersions := map[string]uint16{
		"TLS1.0": tls.VersionTLS10,
		"TLS1.1": tls.VersionTLS11,
		"TLS1.2": tls.VersionTLS12,
		"TLS1.3": tls.VersionTLS13,
	}

	var supportedVersions []string
	for versionName, version := range tlsVersions {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
		}

		conn, err := tls.Dial("tcp", host, config)
		if err == nil {
			supportedVersions = append(supportedVersions, versionName)
			conn.Close()
		}
	}

	// Check for weak TLS versions
	for _, version := range supportedVersions {
		if version == "TLS1.0" || version == "TLS1.1" {
			evidence := fmt.Sprintf("Server supports deprecated TLS version: %s", version)
			finding := CreateTLSFinding(m.Name(), target, evidence, SeverityMedium)
			findingChan <- finding
		}
	}

	// Test for SSLv3 (critical)
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionSSL30,
	}

	conn, err := tls.Dial("tcp", host, config)
	if err == nil {
		conn.Close()
		finding := CreateTLSFinding(m.Name(), target, "Server supports SSLv3 (POODLE vulnerability)", SeverityCritical)
		findingChan <- finding
	}

	// Get certificate info
	config = &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err = tls.Dial("tcp", host, config)
	if err == nil {
		defer conn.Close()
		state := conn.ConnectionState()

		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]

			// Check certificate expiry
			if time.Until(cert.NotAfter) < 30*24*time.Hour {
				evidence := fmt.Sprintf("Certificate expires on %s (less than 30 days)", cert.NotAfter.Format("2006-01-02"))
				finding := CreateTLSFinding(m.Name(), target, evidence, SeverityMedium)
				findingChan <- finding
			}

			// Check if certificate is self-signed
			if cert.IsCA && cert.Subject.CommonName == cert.Issuer.CommonName {
				evidence := "Self-signed certificate detected"
				finding := CreateTLSFinding(m.Name(), target, evidence, SeverityHigh)
				findingChan <- finding
			}
		}
	}
}

// testSecurityHeaders tests for missing security headers
func (m *WebModule) testSecurityHeaders(ctx context.Context, target string, findingChan chan<- Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := m.httpClient.Get(target, nil)
	if err != nil {
		return
	}

	// Check for important security headers
	securityHeaders := map[string]bool{
		"Content-Security-Policy":   true,
		"Strict-Transport-Security": true,
		"X-Frame-Options":           true,
		"X-Content-Type-Options":    true,
		"Referrer-Policy":           false,
		"Permissions-Policy":        false,
		"X-XSS-Protection":          false,
	}

	for header, required := range securityHeaders {
		value := resp.Headers.Get(header)
		if value == "" {
			if required {
				finding := CreateSecurityHeaderFinding(m.Name(), header, true, "")
				findingChan <- finding
			}
		} else {
			// Check for weak values
			lowerValue := strings.ToLower(value)
			if header == "X-Frame-Options" && lowerValue == "allowall" {
				finding := CreateSecurityHeaderFinding(m.Name(), header, false, value)
				findingChan <- finding
			}
			if header == "Strict-Transport-Security" && strings.Contains(lowerValue, "max-age=0") {
				finding := CreateSecurityHeaderFinding(m.Name(), header, false, value)
				findingChan <- finding
			}
		}
	}
}
