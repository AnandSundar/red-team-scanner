package modules

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// HTTPClient is a shared HTTP client for modules
type HTTPClient struct {
	client  *http.Client
	timeout time.Duration
}

// NewHTTPClient creates a new HTTP client for modules
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		timeout: timeout,
	}
}

// Do performs an HTTP request
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// ModuleBase provides common functionality for all modules
type ModuleBase struct {
	name        string
	description string
	httpClient  *HTTPClient
}

// Name returns the module name
func (m *ModuleBase) Name() string {
	return m.name
}

// Description returns the module description
func (m *ModuleBase) Description() string {
	return m.description
}

// SetHTTPClient sets the HTTP client
func (m *ModuleBase) SetHTTPClient(client *HTTPClient) {
	m.httpClient = client
}

// TargetValidator validates target URLs/hosts
type TargetValidator struct{}

// ValidateTarget validates a target string
func (v *TargetValidator) ValidateTarget(target string) error {
	// Basic validation - can be expanded
	if target == "" {
		return ErrInvalidTarget
	}
	return nil
}

// Common errors
var (
	ErrInvalidTarget = FindingError{Message: "invalid target specified"}
	ErrTimeout       = FindingError{Message: "operation timed out"}
	ErrConnection    = FindingError{Message: "connection failed"}
	ErrCancelled     = FindingError{Message: "operation cancelled"}
	ErrRateLimited   = FindingError{Message: "rate limited"}
)

// FindingError represents an error during finding creation
type FindingError struct {
	Message string
	Cause   error
}

func (e FindingError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e FindingError) Unwrap() error {
	return e.Cause
}

// NewFindingError creates a new finding error
func NewFindingError(message string, cause error) FindingError {
	return FindingError{Message: message, Cause: cause}
}

// ============================================================================
// Finding Creation Helpers
// ============================================================================

// CreateFinding creates a standardized finding
func CreateFinding(module string, title string, description string, severity Severity, category string) Finding {
	return Finding{
		ID:          uuid.New(),
		Module:      module,
		Title:       title,
		Description: description,
		Severity:    severity,
		Category:    category,
		Evidence:    FindingEvidence{},
		References:  []string{},
		CVEs:        []string{},
		CreatedAt:   time.Now(),
	}
}

// CreateCriticalFinding creates a critical severity finding
func CreateCriticalFinding(module, title, description, category string) Finding {
	return CreateFinding(module, title, description, SeverityCritical, category)
}

// CreateHighFinding creates a high severity finding
func CreateHighFinding(module, title, description, category string) Finding {
	return CreateFinding(module, title, description, SeverityHigh, category)
}

// CreateMediumFinding creates a medium severity finding
func CreateMediumFinding(module, title, description, category string) Finding {
	return CreateFinding(module, title, description, SeverityMedium, category)
}

// CreateLowFinding creates a low severity finding
func CreateLowFinding(module, title, description, category string) Finding {
	return CreateFinding(module, title, description, SeverityLow, category)
}

// CreateInfoFinding creates an informational finding
func CreateInfoFinding(module, title, description, category string) Finding {
	return CreateFinding(module, title, description, SeverityInfo, category)
}

// CreateFindingWithEvidence creates a finding with evidence
func CreateFindingWithEvidence(module, title, description string, severity Severity, category string, evidence FindingEvidence) Finding {
	finding := CreateFinding(module, title, description, severity, category)
	finding.Evidence = evidence
	return finding
}

// CreatePortFinding creates a finding for an open port
func CreatePortFinding(module string, port int, service string, banner string, isInteresting bool) Finding {
	var severity Severity
	var title, description string

	if isInteresting {
		// Determine severity based on service
		switch service {
		case "Docker":
			severity = SeverityCritical
			title = "Docker Daemon API Exposed"
			description = fmt.Sprintf("Docker daemon API is exposed on port %d without authentication. This allows remote code execution on the host system.", port)
		case "Telnet":
			severity = SeverityHigh
			title = "Telnet Service Exposed"
			description = fmt.Sprintf("Telnet service is running on port %d. Telnet transmits data in cleartext including credentials.", port)
		case "FTP":
			severity = SeverityHigh
			title = "FTP Service Exposed"
			description = fmt.Sprintf("FTP service is running on port %d. Consider using SFTP for secure file transfers.", port)
		case "Redis":
			severity = SeverityCritical
			title = "Redis Database Exposed"
			description = fmt.Sprintf("Redis database is exposed on port %d without authentication. This may allow data access or remote code execution.", port)
		case "MongoDB":
			severity = SeverityCritical
			title = "MongoDB Database Exposed"
			description = fmt.Sprintf("MongoDB database is exposed on port %d. Check for authentication requirements.", port)
		case "MySQL", "PostgreSQL":
			severity = SeverityHigh
			title = fmt.Sprintf("%s Database Exposed", service)
			description = fmt.Sprintf("%s database is accessible on port %d. Verify authentication is properly configured.", service, port)
		default:
			severity = SeverityLow
			title = fmt.Sprintf("%s Service Detected", service)
			description = fmt.Sprintf("%s service is running on port %d.", service, port)
		}
	} else {
		severity = SeverityInfo
		title = fmt.Sprintf("Port %d Open", port)
		description = fmt.Sprintf("Port %d is open with service: %s", port, service)
	}

	finding := CreateFinding(module, title, description, severity, "port-scan")
	finding.Port = port
	finding.Evidence.Details = map[string]interface{}{
		"port":    port,
		"service": service,
		"banner":  banner,
	}

	// Add remediation based on service
	switch service {
	case "Docker":
		finding.Remediation = "Disable Docker TCP socket or enable TLS authentication. Use SSH tunneling for remote access."
		finding.References = []string{"https://docs.docker.com/engine/security/protect-access/"}
	case "Telnet":
		finding.Remediation = "Disable Telnet and use SSH instead. Telnet transmits all data including passwords in cleartext."
		finding.References = []string{"https://tools.ietf.org/html/rfc854"}
	case "FTP":
		finding.Remediation = "Use SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS) instead of plain FTP."
		finding.References = []string{"https://tools.ietf.org/html/rfc4217"}
	case "Redis":
		finding.Remediation = "Enable Redis AUTH, bind to localhost only, or configure firewall rules. Consider using Redis over TLS."
		finding.References = []string{"https://redis.io/topics/security"}
	case "MongoDB":
		finding.Remediation = "Enable MongoDB authentication, bind to specific IPs, and configure firewall rules. Use MongoDB Enterprise for encryption."
		finding.References = []string{"https://docs.mongodb.com/manual/security/"}
	}

	return finding
}

// CreateSecurityHeaderFinding creates a finding for security header issues
func CreateSecurityHeaderFinding(module, header string, missing bool, currentValue string) Finding {
	var title, description, remediation string
	severity := SeverityMedium

	if missing {
		title = fmt.Sprintf("Missing Security Header: %s", header)
		description = fmt.Sprintf("The %s security header is not set. This reduces the security posture of the application.", header)
	} else {
		title = fmt.Sprintf("Weak Security Header: %s", header)
		description = fmt.Sprintf("The %s security header has a weak or insecure value: %s", header, currentValue)
		severity = SeverityLow
	}

	switch header {
	case "Content-Security-Policy":
		remediation = "Implement a Content Security Policy to prevent XSS and data injection attacks. Example: Content-Security-Policy: default-src 'self'"
	case "Strict-Transport-Security":
		remediation = "Enable HSTS to force HTTPS connections. Example: Strict-Transport-Security: max-age=31536000; includeSubDomains"
	case "X-Frame-Options":
		remediation = "Set X-Frame-Options to prevent clickjacking. Example: X-Frame-Options: DENY or SAMEORIGIN"
	case "X-Content-Type-Options":
		remediation = "Prevent MIME type sniffing. Example: X-Content-Type-Options: nosniff"
	case "Referrer-Policy":
		remediation = "Control referrer information. Example: Referrer-Policy: strict-origin-when-cross-origin"
	case "Permissions-Policy":
		remediation = "Restrict browser features. Example: Permissions-Policy: camera=(), microphone=()"
	}

	finding := CreateFinding(module, title, description, severity, "security-headers")
	finding.Remediation = remediation
	finding.References = []string{"https://owasp.org/www-project-secure-headers/"}

	return finding
}

// CreateTechnologyFinding creates a finding for detected technology
func CreateTechnologyFinding(module, name, version, category string) Finding {
	title := fmt.Sprintf("Technology Detected: %s", name)
	if version != "" {
		title += fmt.Sprintf(" %s", version)
	}

	description := fmt.Sprintf("%s was identified as a %s on the target system.", name, category)
	if version != "" {
		description += fmt.Sprintf(" Version %s detected.", version)
	}

	finding := CreateFinding(module, title, description, SeverityInfo, "technology-fingerprinting")
	finding.Evidence.Details = map[string]interface{}{
		"technology": name,
		"version":    version,
		"category":   category,
	}

	return finding
}

// CreateDNSFinding creates a finding for DNS enumeration results
func CreateDNSFinding(module, recordType, name, value string, isSensitive bool) Finding {
	var severity Severity
	var title, description string

	if isSensitive {
		severity = SeverityMedium
		title = fmt.Sprintf("Potentially Sensitive DNS Record: %s", recordType)
		description = fmt.Sprintf("A potentially sensitive %s record was found: %s = %s", recordType, name, value)
	} else {
		severity = SeverityInfo
		title = fmt.Sprintf("DNS %s Record", recordType)
		description = fmt.Sprintf("%s record found: %s = %s", recordType, name, value)
	}

	finding := CreateFinding(module, title, description, severity, "dns-enumeration")
	finding.Evidence.Details = map[string]interface{}{
		"type":  recordType,
		"name":  name,
		"value": value,
	}

	return finding
}

// CreateSubdomainFinding creates a finding for discovered subdomains
func CreateSubdomainFinding(module string, subdomains []string) Finding {
	title := fmt.Sprintf("Subdomain Enumeration Results")
	description := fmt.Sprintf("Discovered %d subdomains during enumeration.", len(subdomains))

	finding := CreateInfoFinding(module, title, description, "subdomain-enumeration")
	finding.Evidence.Details = map[string]interface{}{
		"count":      len(subdomains),
		"subdomains": subdomains,
	}

	return finding
}

// CreateZoneTransferFinding creates a finding for successful zone transfer
func CreateZoneTransferFinding(module, domain, nameserver string, records int) Finding {
	title := "DNS Zone Transfer Successful"
	description := fmt.Sprintf("AXFR (zone transfer) was successful on %s via %s. Retrieved %d records. This exposes the complete DNS infrastructure.", domain, nameserver, records)

	finding := CreateHighFinding(module, title, description, "dns-enumeration")
	finding.Evidence.Details = map[string]interface{}{
		"domain":     domain,
		"nameserver": nameserver,
		"records":    records,
	}
	finding.Remediation = "Disable zone transfers (AXFR) on DNS servers or restrict them to authorized secondary DNS servers only."
	finding.References = []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"}

	return finding
}

// CreateCookieFinding creates a finding for insecure cookie settings
func CreateCookieFinding(module, cookieName, issue string) Finding {
	title := fmt.Sprintf("Insecure Cookie: %s", cookieName)
	description := fmt.Sprintf("Cookie '%s' has insecure settings: %s", cookieName, issue)

	var remediation string
	if issue == "missing Secure flag" {
		remediation = fmt.Sprintf("Set the Secure flag on cookie '%s' to ensure it's only sent over HTTPS connections.", cookieName)
	} else if issue == "missing HttpOnly flag" {
		remediation = fmt.Sprintf("Set the HttpOnly flag on cookie '%s' to prevent JavaScript access.", cookieName)
	} else if issue == "missing SameSite attribute" {
		remediation = fmt.Sprintf("Set SameSite attribute on cookie '%s' to prevent CSRF attacks. Recommended: SameSite=Strict or SameSite=Lax", cookieName)
	}

	finding := CreateMediumFinding(module, title, description, "security-headers")
	finding.Remediation = remediation
	finding.References = []string{"https://owasp.org/www-community/controls/SecureCookieAttribute", "https://owasp.org/www-community/HttpOnly"}

	return finding
}

// ============================================================================
// Rate Limiter
// ============================================================================

// RateLimiter provides rate limiting for requests
type RateLimiter struct {
	ticker *time.Ticker
	done   chan bool
}

// NewRateLimiter creates a rate limiter
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		rps = 10 // Default 10 RPS
	}
	interval := time.Second / time.Duration(rps)
	return &RateLimiter{
		ticker: time.NewTicker(interval),
		done:   make(chan bool),
	}
}

// Wait blocks until the next request is allowed
func (r *RateLimiter) Wait() {
	select {
	case <-r.ticker.C:
	case <-r.done:
	}
}

// Stop stops the rate limiter
func (r *RateLimiter) Stop() {
	r.ticker.Stop()
	close(r.done)
}

// ============================================================================
// Target Type Helpers
// ============================================================================

// TargetType represents the type of target
type TargetType string

const (
	TargetTypeWeb     TargetType = "web"
	TargetTypeAPI     TargetType = "api"
	TargetTypeNetwork TargetType = "network"
	TargetTypeMobile  TargetType = "mobile"
	TargetTypeCloud   TargetType = "cloud"
	TargetTypeUnknown TargetType = "unknown"
)

// AllTargetTypes returns all supported target types
var AllTargetTypes = []TargetType{
	TargetTypeWeb,
	TargetTypeAPI,
	TargetTypeNetwork,
	TargetTypeMobile,
	TargetTypeCloud,
	TargetTypeUnknown,
}

// String returns the string representation
func (t TargetType) String() string {
	return string(t)
}

// IsValid checks if the target type is valid
func (t TargetType) IsValid() bool {
	switch t {
	case TargetTypeWeb, TargetTypeAPI, TargetTypeNetwork, TargetTypeMobile, TargetTypeCloud:
		return true
	}
	return false
}

// ============================================================================
// Context Helpers
// ============================================================================

// CheckContext checks if the context has been cancelled
func CheckContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// WithTimeout creates a context with the specified timeout
func WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// ============================================================================
// Web Application Finding Helpers
// ============================================================================

// CreateXSSFinding creates a finding for XSS vulnerabilities
func CreateXSSFinding(module, targetURL, param, payload string, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("Reflected XSS in Parameter: %s", param)
	description := fmt.Sprintf("A reflected XSS vulnerability was detected in the '%s' parameter. The payload was reflected in the response without proper encoding.", param)

	finding := CreateFinding(module, title, description, SeverityMedium, "xss")
	finding.Evidence = evidence
	finding.Evidence.Payload = payload
	finding.Evidence.URL = targetURL
	finding.Remediation = "Implement proper output encoding for all user-supplied data. Use context-appropriate encoding (HTML entity encoding for HTML context, JavaScript encoding for JS context). Consider implementing a Content Security Policy (CSP)."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/xss/",
		"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
	}

	return finding
}

// CreateSQLiFinding creates a finding for SQL injection vulnerabilities
func CreateSQLiFinding(module, targetURL, param, errorMessage string, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("SQL Injection - Error-based Detection")
	description := fmt.Sprintf("A SQL injection vulnerability was detected in the '%s' parameter. Database error message was returned: %s", param, errorMessage)

	finding := CreateFinding(module, title, description, SeverityHigh, "sql-injection")
	finding.Evidence = evidence
	finding.Evidence.URL = targetURL
	finding.Remediation = "Use parameterized queries (prepared statements) for all database interactions. Never concatenate user input directly into SQL queries. Use an ORM framework that automatically handles parameterization."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/SQL_Injection",
		"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
	}

	return finding
}

// CreateOpenRedirectFinding creates a finding for open redirect vulnerabilities
func CreateOpenRedirectFinding(module, targetURL, param, payload string, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("Open Redirect in Parameter: %s", param)
	description := fmt.Sprintf("An open redirect vulnerability was detected in the '%s' parameter. The application redirects to user-controlled URLs without validation.", param)

	finding := CreateFinding(module, title, description, SeverityLow, "open-redirect")
	finding.Evidence = evidence
	finding.Evidence.Payload = payload
	finding.Evidence.URL = targetURL
	finding.Remediation = "Implement a whitelist of allowed redirect destinations. Use internal mapping (e.g., numeric IDs) instead of direct URLs. Validate redirect URLs against a list of trusted domains."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
		"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
	}

	return finding
}

// CreatePathTraversalFinding creates a finding for path traversal vulnerabilities
func CreatePathTraversalFinding(module, targetURL, param, payload string, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("Path Traversal in Parameter: %s", param)
	description := fmt.Sprintf("A path traversal vulnerability was detected in the '%s' parameter. The application allows access to files outside the intended directory.", param)

	finding := CreateFinding(module, title, description, SeverityHigh, "path-traversal")
	finding.Evidence = evidence
	finding.Evidence.Payload = payload
	finding.Evidence.URL = targetURL
	finding.Remediation = "Validate and sanitize all user-supplied file paths. Use a whitelist of allowed files/directories. Implement proper access controls. Avoid passing user input directly to file system operations."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/Path_Traversal",
		"https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html",
	}

	return finding
}

// CreateCORSFinding creates a finding for CORS misconfigurations
func CreateCORSFinding(module, targetURL, severity, evidence string, allowOrigin string, allowCredentials bool) Finding {
	title := "CORS Misconfiguration"
	sev := SeverityFromString(severity)

	var description string
	if allowCredentials {
		description = fmt.Sprintf("Dangerous CORS configuration detected. The server reflects arbitrary origins ('%s') and allows credentials. This allows attackers to make authenticated cross-origin requests.", allowOrigin)
	} else {
		description = fmt.Sprintf("CORS configuration allows arbitrary origin '%s'. This may allow unauthorized cross-origin requests.", allowOrigin)
	}

	finding := CreateFinding(module, title, description, sev, "cors")
	finding.Evidence = FindingEvidence{
		URL:     targetURL,
		Snippet: evidence,
		Details: map[string]interface{}{
			"allow_origin":      allowOrigin,
			"allow_credentials": allowCredentials,
		},
	}
	finding.Remediation = "Implement a whitelist of allowed origins instead of reflecting arbitrary origins. Avoid using Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Validate the Origin header against a list of trusted domains."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
		"https://portswigger.net/web-security/cors",
	}

	return finding
}

// CreateSensitiveFileFinding creates a finding for exposed sensitive files
func CreateSensitiveFileFinding(module, targetURL, path string, statusCode int, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("Sensitive File Exposed: %s", path)
	description := fmt.Sprintf("A sensitive file was found accessible at %s. This file may contain credentials, configuration data, or other sensitive information.", path)

	var severity Severity
	// Critical for env files and certain configs
	if path == "/.env" || path == "/.env.production" || path == "/wp-config.php" || path == "/config.php" {
		severity = SeverityCritical
	} else if path == "/.git/config" || path == "/backup.sql" || path == "/db.sql" {
		severity = SeverityHigh
	} else {
		severity = SeverityMedium
	}

	finding := CreateFinding(module, title, description, severity, "information-disclosure")
	finding.Evidence = evidence
	finding.Evidence.URL = targetURL
	finding.Evidence.Details = map[string]interface{}{
		"path":        path,
		"status_code": statusCode,
	}
	finding.Remediation = "Remove sensitive files from the web root. Use .htaccess, web.config, or equivalent to deny access to sensitive file patterns. Store sensitive configuration outside the web root."
	finding.References = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
	}

	return finding
}

// CreateDirectoryFinding creates a finding for discovered directories
func CreateDirectoryFinding(module, targetURL, path string, statusCode int) Finding {
	var title, description string
	var severity Severity

	switch statusCode {
	case 200:
		severity = SeverityInfo
		title = fmt.Sprintf("Directory Found: %s", path)
		description = fmt.Sprintf("Directory listing enabled or directory accessible at %s", path)
	case 301, 302, 307, 308:
		severity = SeverityInfo
		title = fmt.Sprintf("Directory Redirect: %s", path)
		description = fmt.Sprintf("Directory found at %s (returns redirect)", path)
	case 403:
		severity = SeverityInfo
		title = fmt.Sprintf("Directory Forbidden: %s", path)
		description = fmt.Sprintf("Directory exists at %s but access is forbidden", path)
	case 401:
		severity = SeverityLow
		title = fmt.Sprintf("Protected Directory: %s", path)
		description = fmt.Sprintf("Directory at %s requires authentication", path)
	default:
		severity = SeverityInfo
		title = fmt.Sprintf("Path Response: %s", path)
		description = fmt.Sprintf("Path %s returned status %d", path, statusCode)
	}

	finding := CreateFinding(module, title, description, severity, "content-discovery")
	finding.Evidence = FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"path":        path,
			"status_code": statusCode,
		},
	}

	return finding
}

// CreateHTTPMethodFinding creates a finding for HTTP method issues
func CreateHTTPMethodFinding(module, targetURL, method string, statusCode int, dangerous bool) Finding {
	var title, description string
	var severity Severity

	if dangerous {
		severity = SeverityMedium
		title = fmt.Sprintf("Dangerous HTTP Method Allowed: %s", method)
		description = fmt.Sprintf("The %s method is allowed and may pose a security risk. This method could allow attackers to modify or delete resources.", method)
	} else {
		severity = SeverityInfo
		title = fmt.Sprintf("HTTP Method Allowed: %s", method)
		description = fmt.Sprintf("The %s method is allowed on this endpoint.", method)
	}

	if method == "TRACE" {
		severity = SeverityMedium
		title = "HTTP TRACE Method Enabled (XST)"
		description = "The TRACE method is enabled, which could allow Cross-Site Tracing (XST) attacks. This can be used to bypass HttpOnly cookie protections."
	}

	finding := CreateFinding(module, title, description, severity, "http-methods")
	finding.Evidence = FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"method":      method,
			"status_code": statusCode,
		},
	}
	finding.Remediation = "Disable unnecessary HTTP methods. Configure the web server to only allow required methods (typically GET, POST, HEAD, OPTIONS). Disable TRACE and TRACK methods."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/Cross_Site_Tracing",
	}

	return finding
}

// CreateTLSFinding creates a finding for TLS/SSL issues
func CreateTLSFinding(module, targetURL, issue string, severity Severity) Finding {
	title := fmt.Sprintf("TLS/SSL Issue: %s", issue)
	description := fmt.Sprintf("A TLS/SSL security issue was identified: %s", issue)

	finding := CreateFinding(module, title, description, severity, "tls-ssl")
	finding.Evidence = FindingEvidence{
		URL:     targetURL,
		Snippet: issue,
	}
	finding.Remediation = "Update TLS configuration to use only secure protocols (TLS 1.2+) and strong cipher suites. Disable deprecated protocols (SSLv3, TLS 1.0, TLS 1.1). Use tools like SSL Labs to test configuration."
	finding.References = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
	}

	return finding
}

// ============================================================================
// API Security Finding Helpers
// ============================================================================

// CreateGraphQLIntrospectionFinding creates a finding for GraphQL introspection
func CreateGraphQLIntrospectionFinding(module, endpoint string, schemaInfo string, evidence FindingEvidence) Finding {
	title := "GraphQL Introspection Enabled"
	description := fmt.Sprintf("GraphQL introspection is enabled on endpoint %s. This allows attackers to discover the entire schema including queries, mutations, types, and fields.", endpoint)
	if schemaInfo != "" {
		description += fmt.Sprintf(" Schema information: %s", schemaInfo)
	}

	finding := CreateCriticalFinding(module, title, description, "graphql-security")
	finding.Evidence = evidence
	finding.Remediation = "Disable introspection in production by setting introspection: false in your GraphQL server configuration. Consider using persisted queries instead."
	finding.References = []string{
		"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		"https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/",
	}

	return finding
}

// CreateGraphQLDepthLimitFinding creates a finding for missing depth limiting
func CreateGraphQLDepthLimitFinding(module, endpoint string, maxDepth int, evidence FindingEvidence) Finding {
	title := "GraphQL Query Depth Limiting Not Enforced"
	description := fmt.Sprintf("The GraphQL endpoint %s does not enforce query depth limits. Successfully executed query with depth %d. This could allow Denial of Service attacks through deeply nested queries.", endpoint, maxDepth)

	finding := CreateHighFinding(module, title, description, "graphql-security")
	finding.Evidence = evidence
	finding.Remediation = "Implement query depth limiting using libraries like graphql-depth-limit. Set a reasonable maximum depth based on your application's needs (typically 10-15)."
	finding.References = []string{
		"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		"https://www.npmjs.com/package/graphql-depth-limit",
	}

	return finding
}

// CreateGraphQLBatchFinding creates a finding for GraphQL batch query support
func CreateGraphQLBatchFinding(module, endpoint string, batchSize int, evidence FindingEvidence) Finding {
	title := "GraphQL Batch Queries Allowed"
	description := fmt.Sprintf("The GraphQL endpoint %s allows batch queries. Successfully sent %d queries in a single request. This could be used for Denial of Service or to bypass rate limiting.", endpoint, batchSize)

	finding := CreateMediumFinding(module, title, description, "graphql-security")
	finding.Evidence = evidence
	finding.Remediation = "Limit the number of queries allowed in a batch request. Consider implementing query cost analysis to prevent expensive batch operations."
	finding.References = []string{
		"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	}

	return finding
}

// CreateGraphQLFieldSuggestionFinding creates a finding for GraphQL field suggestions
func CreateGraphQLFieldSuggestionFinding(module, endpoint string, evidence FindingEvidence) Finding {
	title := "GraphQL Field Suggestions Enabled"
	description := fmt.Sprintf("The GraphQL endpoint %s has field suggestions enabled. Error messages reveal valid field names, which can aid attackers in reconnaissance.", endpoint)

	finding := CreateLowFinding(module, title, description, "graphql-security")
	finding.Evidence = evidence
	finding.Remediation = "Disable field suggestions in production by setting the appropriate configuration option in your GraphQL server."
	finding.References = []string{
		"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	}

	return finding
}

// CreateGraphQLInjectionFinding creates a finding for GraphQL injection vulnerabilities
func CreateGraphQLInjectionFinding(module, endpoint string, payload string, errorMsg string, evidence FindingEvidence) Finding {
	title := "GraphQL Injection Vulnerability"
	description := fmt.Sprintf("Potential injection vulnerability detected on GraphQL endpoint %s. Payload '%s' triggered a database or system error: %s", endpoint, payload, errorMsg)

	finding := CreateHighFinding(module, title, description, "graphql-security")
	finding.Evidence = evidence
	finding.Evidence.Payload = payload
	finding.Remediation = "Implement proper input validation and sanitization in GraphQL resolvers. Use parameterized queries and avoid concatenating user input into database queries or system commands."
	finding.References = []string{
		"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		"https://owasp.org/www-community/attacks/SQL_Injection",
	}

	return finding
}

// CreateWebSocketOriginFinding creates a finding for missing WebSocket origin validation
func CreateWebSocketOriginFinding(module, endpoint string, evidence FindingEvidence) Finding {
	title := "WebSocket Missing Origin Validation"
	description := fmt.Sprintf("The WebSocket endpoint %s does not validate the Origin header. This allows Cross-Site WebSocket Hijacking (CSWSH) attacks where malicious websites can establish WebSocket connections on behalf of authenticated users.", endpoint)

	finding := CreateHighFinding(module, title, description, "websocket-security")
	finding.Evidence = evidence
	finding.Remediation = "Implement strict Origin header validation. Only allow connections from trusted origins. Consider using CSRF tokens for WebSocket authentication."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/Cross-Site_WebSocket_Hijacking",
		"https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
	}

	return finding
}

// CreateWebSocketAuthFinding creates a finding for WebSocket authentication issues
func CreateWebSocketAuthFinding(module, endpoint string, issue string, evidence FindingEvidence) Finding {
	title := "WebSocket Authentication Bypass"
	description := fmt.Sprintf("WebSocket endpoint %s has authentication issues: %s", endpoint, issue)

	finding := CreateHighFinding(module, title, description, "websocket-security")
	finding.Evidence = evidence
	finding.Remediation = "Implement proper authentication for WebSocket connections. Validate authentication tokens during the handshake phase and maintain session state. Do not rely solely on cookie-based authentication."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/Cross-Site_WebSocket_Hijacking",
	}

	return finding
}

// CreateWebSocketXSSFinding creates a finding for WebSocket XSS
func CreateWebSocketXSSFinding(module, endpoint string, payload string, evidence FindingEvidence) Finding {
	title := "WebSocket Cross-Site Scripting (XSS)"
	description := fmt.Sprintf("XSS payload was reflected through WebSocket endpoint %s. The payload '%s' was echoed back without proper sanitization, potentially allowing stored or reflected XSS attacks.", endpoint, payload)

	finding := CreateMediumFinding(module, title, description, "websocket-security")
	finding.Evidence = evidence
	finding.Evidence.Payload = payload
	finding.Remediation = "Implement output encoding for all data sent through WebSockets. Validate and sanitize all incoming messages before broadcasting to other clients."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/xss/",
		"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
	}

	return finding
}

// CreateIDORFinding creates a finding for IDOR vulnerabilities
func CreateIDORFinding(module, endpoint string, originalID, accessedID string, evidence FindingEvidence) Finding {
	title := "Insecure Direct Object Reference (IDOR)"
	description := fmt.Sprintf("IDOR vulnerability detected on endpoint %s. Successfully accessed resource ID '%s' (original ID was '%s'). The application does not properly verify authorization for object access.", endpoint, accessedID, originalID)

	finding := CreateHighFinding(module, title, description, "idor")
	finding.Evidence = evidence
	finding.Evidence.Details = map[string]interface{}{
		"original_id": originalID,
		"accessed_id": accessedID,
		"endpoint":    endpoint,
	}
	finding.Remediation = "Implement proper authorization checks for all object access. Use indirect reference maps (e.g., UUIDs instead of sequential IDs) and verify the user has permission to access the requested resource."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
		"https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
	}

	return finding
}

// CreateMassAssignmentFinding creates a finding for mass assignment vulnerabilities
func CreateMassAssignmentFinding(module, endpoint string, field string, evidence FindingEvidence) Finding {
	title := "Mass Assignment Vulnerability"
	description := fmt.Sprintf("Mass assignment vulnerability detected on endpoint %s. The field '%s' was accepted and potentially modified without proper validation. This could allow privilege escalation or unauthorized data modification.", endpoint, field)

	finding := CreateHighFinding(module, title, description, "mass-assignment")
	finding.Evidence = evidence
	finding.Evidence.Details = map[string]interface{}{
		"field":    field,
		"endpoint": endpoint,
	}
	finding.Remediation = "Implement a whitelist of allowed fields for updates. Use Data Transfer Objects (DTOs) instead of binding directly to domain models. Validate all input before processing."
	finding.References = []string{
		"https://owasp.org/www-community/Mass_Assignment",
		"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
	}

	return finding
}

// CreateAPIDiscoveryFinding creates a finding for discovered API endpoints
func CreateAPIDiscoveryFinding(module, endpoint string, endpointType string, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("API Endpoint Discovered: %s", endpoint)
	description := fmt.Sprintf("Discovered %s API endpoint at %s during enumeration.", endpointType, endpoint)

	var severity Severity
	switch endpointType {
	case "admin", "internal", "management":
		severity = SeverityMedium
	case "swagger", "openapi", "docs":
		severity = SeverityLow
	default:
		severity = SeverityInfo
	}

	finding := CreateFinding(module, title, description, severity, "api-discovery")
	finding.Evidence = evidence
	finding.Evidence.Details = map[string]interface{}{
		"endpoint":      endpoint,
		"endpoint_type": endpointType,
	}

	return finding
}

// CreateAPIRateLimitFinding creates a finding for missing rate limiting
func CreateAPIRateLimitFinding(module, endpoint string, requests int, window time.Duration, evidence FindingEvidence) Finding {
	title := "API Rate Limiting Not Enforced"
	description := fmt.Sprintf("No rate limiting detected on endpoint %s. Successfully sent %d requests within %s without receiving HTTP 429 (Too Many Requests). This could allow brute force attacks or Denial of Service.", endpoint, requests, window)

	finding := CreateMediumFinding(module, title, description, "api-security")
	finding.Evidence = evidence
	finding.Evidence.Details = map[string]interface{}{
		"requests":    requests,
		"time_window": window.String(),
		"endpoint":    endpoint,
	}
	finding.Remediation = "Implement rate limiting using tools like Redis, API gateways, or framework-specific middleware. Set appropriate limits based on endpoint sensitivity (e.g., stricter limits for authentication endpoints)."
	finding.References = []string{
		"https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
		"https://owasp.org/www-community/attacks/Denial_of_Service",
	}

	return finding
}

// CreateAPIAuthFinding creates a finding for API authentication issues
func CreateAPIAuthFinding(module, endpoint string, issue string, evidence FindingEvidence) Finding {
	title := "API Authentication Weakness"
	description := fmt.Sprintf("Authentication issue detected on endpoint %s: %s", endpoint, issue)

	finding := CreateHighFinding(module, title, description, "api-authentication")
	finding.Evidence = evidence
	finding.Remediation = "Implement strong authentication mechanisms. Use OAuth 2.0 or JWT with proper validation. Ensure all sensitive endpoints require authentication."
	finding.References = []string{
		"https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
		"https://owasp.org/www-community/attacks/Session_hijacking_attack",
	}

	return finding
}

// CreateAPIVerboseErrorFinding creates a finding for verbose error messages
func CreateAPIVerboseErrorFinding(module, endpoint string, errorDetail string, evidence FindingEvidence) Finding {
	title := "Verbose Error Messages in API"
	description := fmt.Sprintf("The API endpoint %s returns verbose error messages that may leak sensitive information: %s", endpoint, errorDetail)

	finding := CreateMediumFinding(module, title, description, "api-security")
	finding.Evidence = evidence
	finding.Remediation = "Implement generic error messages for API responses. Log detailed errors server-side but return user-friendly messages to clients. Avoid exposing stack traces, internal paths, or database details."
	finding.References = []string{
		"https://owasp.org/www-community/Improper_Error_Handling",
		"https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
	}

	return finding
}

// CreateHTTPVerbTamperingFinding creates a finding for HTTP verb tampering
func CreateHTTPVerbTamperingFinding(module, endpoint, method string, statusCode int, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("HTTP Verb Tampering: %s Allowed", method)
	description := fmt.Sprintf("The endpoint %s accepts %s requests and returns status %d. This may allow unauthorized access or modification of resources through alternative HTTP methods.", endpoint, method, statusCode)

	finding := CreateMediumFinding(module, title, description, "http-verb-tampering")
	finding.Evidence = evidence
	finding.Evidence.Details = map[string]interface{}{
		"method":      method,
		"status_code": statusCode,
		"endpoint":    endpoint,
	}
	finding.Remediation = "Implement proper authorization checks for all HTTP methods. Explicitly define allowed methods for each endpoint and reject all others. Use framework features like route annotations."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/HTTP_Method_Tampering",
		"https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
	}

	return finding
}

// CreateOpenAPIExposureFinding creates a finding for exposed API documentation
func CreateOpenAPIExposureFinding(module, endpoint, docType string, evidence FindingEvidence) Finding {
	title := fmt.Sprintf("API Documentation Exposed: %s", docType)
	description := fmt.Sprintf("API documentation (%s) is publicly accessible at %s. This exposes the complete API structure including endpoints, parameters, and authentication methods to potential attackers.", docType, endpoint)

	finding := CreateMediumFinding(module, title, description, "api-security")
	finding.Evidence = evidence
	finding.Evidence.Details = map[string]interface{}{
		"documentation_type": docType,
		"endpoint":           endpoint,
	}
	finding.Remediation = "Restrict access to API documentation in production. Implement authentication for documentation endpoints or host them separately from the production API."
	finding.References = []string{
		"https://owasp.org/www-project-api-security/",
	}

	return finding
}

// ============================================================================
// OWASP Agentic AI (ASI) Finding Helpers
// ============================================================================

// CreateASIPromptInjectionFinding creates a finding for prompt injection vulnerabilities
func CreateASIPromptInjectionFinding(module, targetURL string, payload string, success bool, responseContent string) Finding {
	var severity Severity
	var title, description string

	if success {
		severity = SeverityHigh
		title = "ASI-01: Prompt Injection Vulnerability"
		description = "Successfully executed prompt injection attack. The AI system processed malicious instructions that override its intended behavior, allowing potential data extraction or behavior manipulation."
	} else {
		severity = SeverityMedium
		title = "ASI-01: Potential Prompt Injection Weakness"
		description = "The AI system showed signs of prompt injection vulnerability. While the attack was not fully successful, the response patterns suggest weaknesses in prompt handling."
	}

	evidence := FindingEvidence{
		URL:     targetURL,
		Payload: payload,
		Snippet: responseContent,
		Details: map[string]interface{}{
			"asi_category":   "ASI01",
			"injection_type": "prompt_injection",
			"successful":     success,
			"vulnerability":  "Agent Goal Hijacking",
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_injection")
	finding.Evidence = evidence
	finding.Remediation = "Implement input validation and sanitization for all prompts. Use prompt engineering techniques like delimiters and role boundaries. Consider using prompt filtering services. Implement output encoding to prevent data leakage."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
		"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
	}

	return finding
}

// CreateASISystemPromptLeakFinding creates a finding for system prompt disclosure
func CreateASISystemPromptLeakFinding(module, targetURL string, leakedContent string, confidence float64) Finding {
	var severity Severity
	if confidence > 0.8 {
		severity = SeverityCritical
	} else if confidence > 0.5 {
		severity = SeverityHigh
	} else {
		severity = SeverityMedium
	}

	title := "ASI-01: System Prompt Information Disclosure"
	description := fmt.Sprintf("The AI system leaked portions of its system prompt or configuration information. Confidence level: %.0f%%. This information can be used to craft more effective injection attacks.", confidence*100)

	evidence := FindingEvidence{
		URL:     targetURL,
		Snippet: leakedContent,
		Details: map[string]interface{}{
			"asi_category": "ASI01",
			"confidence":   confidence,
			"leak_type":    "system_prompt",
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_injection")
	finding.Evidence = evidence
	finding.Remediation = "Implement output filtering to prevent system prompt disclosure. Use separate context windows for system instructions. Consider using confidential computing for sensitive prompts."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASIToolMisuseFinding creates a finding for tool/function misuse vulnerabilities
func CreateASIToolMisuseFinding(module, targetURL, toolName, issue string, evidence FindingEvidence) Finding {
	var severity Severity
	switch issue {
	case "unauthorized_execution":
		severity = SeverityHigh
	case "information_disclosure":
		severity = SeverityMedium
	case "rate_limit_bypass":
		severity = SeverityMedium
	default:
		severity = SeverityLow
	}

	title := fmt.Sprintf("ASI-02: Tool Misuse - %s", toolName)
	description := fmt.Sprintf("The AI agent demonstrated tool misuse vulnerability through %s. The tool '%s' was accessed or used in an unintended manner.", issue, toolName)

	evidence.Details = map[string]interface{}{
		"asi_category": "ASI02",
		"tool_name":    toolName,
		"issue_type":   issue,
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_tools")
	finding.Evidence = evidence
	finding.Remediation = "Implement strict authorization for tool access. Validate all tool inputs and outputs. Use least-privilege principles for tool permissions. Implement comprehensive audit logging for all tool executions."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASIToolEnumerationFinding creates a finding when AI reveals available tools
func CreateASIToolEnumerationFinding(module, targetURL string, tools []string) Finding {
	severity := SeverityLow
	if len(tools) > 0 {
		severity = SeverityMedium
	}

	title := "ASI-02: Tool Enumeration - Available Tools Exposed"
	description := fmt.Sprintf("The AI system revealed %d available tools/functions when queried. This information disclosure can aid attackers in crafting targeted attacks.", len(tools))

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category": "ASI02",
			"tools":        tools,
			"tool_count":   len(tools),
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_tools")
	finding.Evidence = evidence
	finding.Remediation = "Train the AI to not disclose internal tool implementations. Use system prompts that prevent tool enumeration. Implement filtering on outputs that mention tool details."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASIPrivilegeEscalationFinding creates a finding for identity/privilege abuse
func CreateASIPrivilegeEscalationFinding(module, targetURL, method string, success bool) Finding {
	var severity Severity
	if success {
		severity = SeverityCritical
	} else {
		severity = SeverityHigh
	}

	title := "ASI-03: Identity and Privilege Abuse"
	description := fmt.Sprintf("Privilege escalation attempt via '%s' was detected. Success: %v. The AI system may be vulnerable to role impersonation or session hijacking attacks.", method, success)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category":  "ASI03",
			"method":        method,
			"successful":    success,
			"vulnerability": "Privilege Escalation",
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_privilege")
	finding.Evidence = evidence
	finding.Remediation = "Implement strong authentication and authorization checks independent of AI responses. Validate user identities through secure tokens. Never rely on AI for security decisions. Implement session management with proper validation."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASICodeExecutionFinding creates a finding for code execution vulnerabilities
func CreateASICodeExecutionFinding(module, targetURL, payload string, output string, executionType string) Finding {
	severity := SeverityCritical
	title := fmt.Sprintf("ASI-05: Unexpected Code Execution (%s)", executionType)
	description := fmt.Sprintf("The AI system executed unauthorized code via %s. This represents a critical security vulnerability allowing arbitrary code execution.", executionType)

	evidence := FindingEvidence{
		URL:     targetURL,
		Payload: payload,
		Snippet: output,
		Details: map[string]interface{}{
			"asi_category":   "ASI05",
			"execution_type": executionType,
			"output":         output,
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_code_execution")
	finding.Evidence = evidence
	finding.Remediation = "Implement strict sandboxing for code execution environments. Use containerization with minimal privileges. Implement input validation and sanitization. Disable dangerous functions and system calls. Monitor and log all code execution."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
		"https://owasp.org/www-community/attacks/Code_Injection",
	}

	return finding
}

// CreateASISSRFFinding creates a finding for Server-Side Request Forgery via AI
func CreateASISSRFFinding(module, targetURL, targetEndpoint string, responseContent string) Finding {
	severity := SeverityHigh
	title := "ASI-05: Server-Side Request Forgery via AI"
	description := fmt.Sprintf("The AI system made unauthorized requests to internal endpoint %s. This SSRF vulnerability can be exploited to access internal services and cloud metadata.", targetEndpoint)

	evidence := FindingEvidence{
		URL:     targetURL,
		Snippet: responseContent,
		Details: map[string]interface{}{
			"asi_category":    "ASI05",
			"target_endpoint": targetEndpoint,
			"vulnerability":   "SSRF",
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_code_execution")
	finding.Evidence = evidence
	finding.Remediation = "Implement strict allowlists for outbound URLs. Block access to internal IP ranges and metadata endpoints. Use network segmentation to isolate AI services. Validate all URLs before making requests."
	finding.References = []string{
		"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
	}

	return finding
}

// CreateASIMemoryPoisoningFinding creates a finding for memory/context poisoning
func CreateASIMemoryPoisoningFinding(module, targetURL string, poisonType string, persisted bool) Finding {
	var severity Severity
	if persisted {
		severity = SeverityHigh
	} else {
		severity = SeverityMedium
	}

	title := "ASI-06: Memory and Context Poisoning"
	description := fmt.Sprintf("Context poisoning attack via '%s' was successful. Persistence: %v. Malicious instructions may have been injected into the conversation context.", poisonType, persisted)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category": "ASI06",
			"poison_type":  poisonType,
			"persisted":    persisted,
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_memory")
	finding.Evidence = evidence
	finding.Remediation = "Implement context isolation between conversations. Validate and sanitize all context inputs. Use separate storage for user inputs and system instructions. Implement context integrity checks."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASIRAGPoisoningFinding creates a finding for RAG document poisoning
func CreateASIRAGPoisoningFinding(module, targetURL string, documentType string, sqlInjected bool) Finding {
	var severity Severity
	if sqlInjected {
		severity = SeverityCritical
	} else {
		severity = SeverityHigh
	}

	title := "ASI-06: RAG Document Poisoning"
	description := fmt.Sprintf("RAG system is vulnerable to document poisoning via %s. SQL Injection: %v. Malicious documents can manipulate retrieval results.", documentType, sqlInjected)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category":  "ASI06",
			"document_type": documentType,
			"sql_injection": sqlInjected,
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_memory")
	finding.Evidence = evidence
	finding.Remediation = "Sanitize all documents before ingestion. Implement input validation for RAG queries. Use parameterized queries for document retrieval. Implement content filtering on retrieved documents."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASIInterAgentCommFinding creates a finding for insecure inter-agent communication
func CreateASIInterAgentCommFinding(module, targetURL, issue string, unauthenticated bool) Finding {
	var severity Severity
	if unauthenticated {
		severity = SeverityHigh
	} else {
		severity = SeverityMedium
	}

	title := "ASI-07: Insecure Inter-Agent Communication"
	description := fmt.Sprintf("Inter-agent communication vulnerability: %s. Unauthenticated access: %v. Agent-to-agent messages may be intercepted or forged.", issue, unauthenticated)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category":    "ASI07",
			"issue":           issue,
			"unauthenticated": unauthenticated,
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_communication")
	finding.Evidence = evidence
	finding.Remediation = "Implement mutual TLS for agent-to-agent communication. Use message authentication and integrity verification. Implement proper origin validation. Encrypt all inter-agent messages."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASICascadingFailureFinding creates a finding for cascading failure vulnerabilities
func CreateASICascadingFailureFinding(module, targetURL, failureType string, timeout bool) Finding {
	severity := SeverityMedium
	if timeout {
		severity = SeverityHigh
	}

	title := "ASI-08: Cascading Failure Vulnerability"
	description := fmt.Sprintf("The AI system is vulnerable to cascading failures via %s. Caused timeout: %v. Malformed inputs can cause system instability.", failureType, timeout)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category": "ASI08",
			"failure_type": failureType,
			"timeout":      timeout,
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_stability")
	finding.Evidence = evidence
	finding.Remediation = "Implement input size limits and timeouts. Use circuit breakers for resource-intensive operations. Implement proper error handling. Monitor resource consumption and implement rate limiting."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASITrustExploitationFinding creates a finding for trust exploitation attempts
func CreateASITrustExploitationFinding(module, targetURL, persona string, bypassed bool) Finding {
	var severity Severity
	if bypassed {
		severity = SeverityHigh
	} else {
		severity = SeverityMedium
	}

	title := "ASI-09: Human-Agent Trust Exploitation"
	description := fmt.Sprintf("Trust exploitation attempt using '%s' persona. Safety bypass: %v. The AI system may be vulnerable to authority-based manipulation.", persona, bypassed)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category": "ASI09",
			"persona":      persona,
			"bypassed":     bypassed,
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_trust")
	finding.Evidence = evidence
	finding.Remediation = "Implement multi-layered safety checks. Train models to recognize false authority claims. Use consistent safety policies regardless of claimed context. Implement human-in-the-loop for sensitive operations."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASIRogueAgentFinding creates a finding for rogue agent behavior
func CreateASIRogueAgentFinding(module, targetURL, behavior string, severityLevel string) Finding {
	var severity Severity
	switch severityLevel {
	case "critical":
		severity = SeverityCritical
	case "high":
		severity = SeverityHigh
	case "medium":
		severity = SeverityMedium
	default:
		severity = SeverityLow
	}

	title := "ASI-10: Rogue Agent Behavior Detected"
	description := fmt.Sprintf("Rogue agent behavior detected: %s. The AI system performed actions outside its intended scope or without proper authorization.", behavior)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"asi_category": "ASI10",
			"behavior":     behavior,
		},
	}

	finding := CreateFinding(module, title, description, severity, "agentic_ai_behavior")
	finding.Evidence = evidence
	finding.Remediation = "Implement strict scope enforcement. Use capability-based access control. Require confirmation for irreversible actions. Implement comprehensive audit logging. Monitor for anomalous agent behavior."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// CreateASIAIDetectedFinding creates an informational finding for AI detection
func CreateASIAIDetectedFinding(module, targetURL string, aiType string, endpoints []string) Finding {
	title := "AI/LLM Interface Detected"
	description := fmt.Sprintf("Detected %s AI interface at the target. Available endpoints: %v", aiType, endpoints)

	evidence := FindingEvidence{
		URL: targetURL,
		Details: map[string]interface{}{
			"ai_type":   aiType,
			"endpoints": endpoints,
		},
	}

	finding := CreateInfoFinding(module, title, description, "agentic_ai_detection")
	finding.Evidence = evidence
	finding.Remediation = "Ensure all AI interfaces are properly secured. Implement authentication for AI endpoints. Monitor AI interactions for suspicious patterns."
	finding.References = []string{
		"https://genai.owasp.org/llm-top-10/",
	}

	return finding
}

// TargetType for AI/LLM applications
const (
	TargetTypeAILLMApp TargetType = "ai_llm_app"
)

// AIASIToCVSS maps ASI categories to CVSS scores
func AIASIToCVSS(category string, severity Severity) float64 {
	baseScores := map[string]float64{
		"ASI01": 8.1, // Prompt Injection
		"ASI02": 7.5, // Tool Misuse
		"ASI03": 8.8, // Privilege Escalation
		"ASI04": 6.5, // Supply Chain
		"ASI05": 9.8, // Code Execution
		"ASI06": 7.2, // Memory Poisoning
		"ASI07": 7.0, // Inter-Agent Comm
		"ASI08": 5.3, // Cascading Failures
		"ASI09": 6.8, // Trust Exploitation
		"ASI10": 8.0, // Rogue Agent
	}

	baseScore, exists := baseScores[category]
	if !exists {
		baseScore = 5.0
	}

	// Adjust based on severity
	switch severity {
	case SeverityCritical:
		return float64Min(baseScore+1.0, 10.0)
	case SeverityHigh:
		return baseScore
	case SeverityMedium:
		return float64Max(baseScore-2.0, 4.0)
	case SeverityLow:
		return float64Max(baseScore-4.0, 2.0)
	default:
		return baseScore
	}
}

func float64Min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func float64Max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ============================================================================
// Threat Intelligence Finding Helpers
// ============================================================================

// CreateAbuseIPDBFinding creates a finding for IP reputation from AbuseIPDB
func CreateAbuseIPDBFinding(module, ip string, abuseScore int, reports int, isTor bool, categories []string) Finding {
	var severity Severity
	var title, description string

	if abuseScore >= 75 {
		severity = SeverityCritical
		title = "IP Address on AbuseIPDB Blacklist"
		description = fmt.Sprintf("IP %s has a high abuse confidence score of %d%% based on %d reports. Categories: %v. This IP is actively used for malicious activities.", ip, abuseScore, reports, categories)
	} else if abuseScore >= 25 {
		severity = SeverityHigh
		title = "IP Address with Suspicious Activity"
		description = fmt.Sprintf("IP %s has an abuse confidence score of %d%% based on %d reports. This IP has been reported for suspicious activity.", ip, abuseScore, reports)
	} else if abuseScore > 0 {
		severity = SeverityMedium
		title = "IP Address with Minor Abuse Reports"
		description = fmt.Sprintf("IP %s has an abuse confidence score of %d%% based on %d reports.", ip, abuseScore, reports)
	} else {
		severity = SeverityInfo
		title = "IP Address Clean on AbuseIPDB"
		description = fmt.Sprintf("IP %s has no abuse reports (0%% confidence score).", ip)
	}

	if isTor {
		severity = SeverityHigh
		title += " (Tor Exit Node)"
		description += " This IP is identified as a Tor exit node."
	}

	finding := CreateFinding(module, title, description, severity, "threat-intel")
	finding.Evidence = FindingEvidence{
		Details: map[string]interface{}{
			"ip":            ip,
			"abuse_score":   abuseScore,
			"total_reports": reports,
			"is_tor":        isTor,
			"categories":    categories,
			"source":        "abuseipdb",
		},
	}
	finding.Remediation = "Consider blocking or rate-limiting traffic from this IP. Review access logs for suspicious activity. If this is a legitimate IP that has been compromised, consider contacting the owner."
	finding.References = []string{"https://www.abuseipdb.com/"}

	return finding
}

// CreateURLhausFinding creates a finding for URL/domain malware detection
func CreateURLhausFinding(module, domain string, isMalicious bool, threat string, payloads int) Finding {
	var severity Severity
	title := fmt.Sprintf("Domain on URLhaus Malware List: %s", domain)

	if isMalicious {
		severity = SeverityCritical
	} else {
		severity = SeverityInfo
		title = fmt.Sprintf("Domain Checked on URLhaus: %s", domain)
	}

	description := fmt.Sprintf("Domain %s was checked against URLhaus malware database. Status: %s. Threat type: %s. Associated payloads: %d.",
		domain, map[bool]string{true: "Malicious", false: "Clean"}[isMalicious], threat, payloads)

	finding := CreateFinding(module, title, description, severity, "threat-intel")
	finding.Evidence = FindingEvidence{
		Details: map[string]interface{}{
			"domain":       domain,
			"is_malicious": isMalicious,
			"threat_type":  threat,
			"payloads":     payloads,
			"source":       "urlhaus",
		},
	}
	finding.Remediation = "Immediately block access to this domain if confirmed malicious. Check systems for signs of compromise. Update DNS and firewall rules to prevent access."
	finding.References = []string{"https://urlhaus.abuse.ch/"}

	return finding
}

// CreateCVEFinding creates a finding for CVE detected in technology
func CreateCVEFinding(module, techName, techVersion string, cveID string, cvss float64, description string, isKEV bool) Finding {
	var severity Severity
	if cvss >= 9.0 {
		severity = SeverityCritical
	} else if cvss >= 7.0 {
		severity = SeverityHigh
	} else if cvss >= 4.0 {
		severity = SeverityMedium
	} else {
		severity = SeverityLow
	}

	title := fmt.Sprintf("Known CVE for %s %s: %s", techName, techVersion, cveID)
	if isKEV {
		severity = SeverityCritical
		title = fmt.Sprintf("Known Exploited Vulnerability (KEV) for %s %s: %s", techName, techVersion, cveID)
	}

	desc := fmt.Sprintf("%s version %s has a known vulnerability: %s. CVSS Score: %.1f. Description: %s",
		techName, techVersion, cveID, cvss, description)
	if isKEV {
		desc += " This CVE is listed in CISA's Known Exploited Vulnerabilities Catalog and is actively being exploited in the wild."
	}

	finding := CreateFinding(module, title, desc, severity, "cve")
	finding.CVEs = []string{cveID}
	finding.CVSS = cvss
	finding.Evidence = FindingEvidence{
		Details: map[string]interface{}{
			"technology": techName,
			"version":    techVersion,
			"cve_id":     cveID,
			"cvss_score": cvss,
			"is_kev":     isKEV,
			"source":     "nvd",
		},
	}
	finding.Remediation = fmt.Sprintf("Update %s to the latest version immediately. If patching is not possible, consider implementing compensating controls such as WAF rules, network segmentation, or access restrictions. Monitor for exploitation attempts.", techName)
	finding.References = []string{
		fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
		"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	}

	return finding
}

// CreateShodanFinding creates a finding for Shodan intelligence
func CreateShodanFinding(module, ip string, ports []int, vulns []string, tags []string, riskScore int) Finding {
	var severity Severity

	if len(vulns) > 0 {
		severity = SeverityHigh
	} else if riskScore >= 20 {
		severity = SeverityMedium
	} else if riskScore > 0 {
		severity = SeverityLow
	} else {
		severity = SeverityInfo
	}

	title := fmt.Sprintf("Shodan Intelligence Available for %s", ip)
	description := fmt.Sprintf("Shodan InternetDB has data for IP %s. Open ports: %v. Tags: %v.", ip, ports, tags)
	if len(vulns) > 0 {
		description += fmt.Sprintf(" Known CVEs: %v.", vulns)
	}

	finding := CreateFinding(module, title, description, severity, "threat-intel")
	finding.Evidence = FindingEvidence{
		Details: map[string]interface{}{
			"ip":         ip,
			"ports":      ports,
			"vulns":      vulns,
			"tags":       tags,
			"risk_score": riskScore,
			"source":     "shodan",
		},
	}
	finding.Remediation = "Review the exposed ports and services. Close unnecessary ports. Apply security patches for known CVEs. Consider using a firewall to restrict access to sensitive services."
	finding.References = []string{"https://www.shodan.io/"}

	return finding
}

// CreateCertificateTransparencyFinding creates a finding for CT log data
func CreateCertificateTransparencyFinding(module, domain string, subdomainCount int, subdomains []string) Finding {
	severity := SeverityInfo
	if subdomainCount > 50 {
		severity = SeverityLow
	}

	title := fmt.Sprintf("Certificate Transparency Data for %s", domain)
	description := fmt.Sprintf("Found %d certificates for %s and its subdomains in Certificate Transparency logs.", subdomainCount, domain)

	finding := CreateFinding(module, title, description, severity, "threat-intel")
	finding.Evidence = FindingEvidence{
		Details: map[string]interface{}{
			"domain":          domain,
			"cert_count":      subdomainCount,
			"subdomains":      subdomains,
			"subdomain_count": len(subdomains),
			"source":          "certificate_transparency",
		},
	}
	finding.Remediation = "Review discovered subdomains to ensure they are all properly secured and monitored. Check for unintended subdomain exposure."
	finding.References = []string{"https://crt.sh/"}

	return finding
}

// CreateThreatIntelSummaryFinding creates a summary finding for all intel
func CreateThreatIntelSummaryFinding(module string, sourcesChecked []string, findingsCount int, enrichmentData map[string]interface{}) Finding {
	title := "Threat Intelligence Enrichment Summary"
	description := fmt.Sprintf("Threat intelligence enrichment completed. Sources checked: %v. Total findings from enrichment: %d.", sourcesChecked, findingsCount)

	finding := CreateInfoFinding(module, title, description, "threat-intel")
	finding.Evidence = FindingEvidence{
		Details: map[string]interface{}{
			"sources":        sourcesChecked,
			"findings_count": findingsCount,
			"enrichment":     enrichmentData,
		},
	}
	finding.References = []string{
		"https://www.abuseipdb.com/",
		"https://urlhaus.abuse.ch/",
		"https://nvd.nist.gov/",
		"https://www.shodan.io/",
	}

	return finding
}
