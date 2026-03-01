package modules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Severity represents finding severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// String returns the string representation of severity
func (s Severity) String() string {
	return string(s)
}

// Score returns a numeric score for severity comparison
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// IsValid checks if the severity is valid
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Finding represents a security finding
type Finding struct {
	ID          uuid.UUID       `json:"id"`
	ScanID      uuid.UUID       `json:"scan_id"`
	Module      string          `json:"module"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    Severity        `json:"severity"`
	Category    string          `json:"category"`
	Evidence    FindingEvidence `json:"evidence"`
	Remediation string          `json:"remediation"`
	CVSS        float64         `json:"cvss,omitempty"`
	CVEs        []string        `json:"cves,omitempty"`
	References  []string        `json:"references"`
	CreatedAt   time.Time       `json:"created_at"`
	Target      string          `json:"target,omitempty"`
	Port        int             `json:"port,omitempty"`
}

// FindingEvidence contains evidence for a finding
type FindingEvidence struct {
	Request    string                 `json:"request,omitempty"`
	Response   string                 `json:"response,omitempty"`
	Headers    map[string]string      `json:"headers,omitempty"`
	Payload    string                 `json:"payload,omitempty"`
	Snippet    string                 `json:"snippet,omitempty"`
	URL        string                 `json:"url,omitempty"`
	Screenshot string                 `json:"screenshot,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// FindingSummary provides a summary of findings by severity
type FindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Add increments the count for a severity level
func (fs *FindingSummary) Add(severity Severity) {
	switch severity {
	case SeverityCritical:
		fs.Critical++
	case SeverityHigh:
		fs.High++
	case SeverityMedium:
		fs.Medium++
	case SeverityLow:
		fs.Low++
	case SeverityInfo:
		fs.Info++
	}
	fs.Total++
}

// ============================================================================
// Finding Creation Helpers
// ============================================================================

// NewFinding creates a new finding with default values
func NewFinding(module, title, description string, severity Severity, category string) Finding {
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

// NewFindingWithEvidence creates a new finding with evidence
func NewFindingWithEvidence(module, title, description string, severity Severity, category string, evidence FindingEvidence) Finding {
	finding := NewFinding(module, title, description, severity, category)
	finding.Evidence = evidence
	return finding
}

// WithTarget sets the target for a finding
func (f Finding) WithTarget(target string) Finding {
	f.Target = target
	return f
}

// WithPort sets the port for a finding
func (f Finding) WithPort(port int) Finding {
	f.Port = port
	return f
}

// WithCVSS sets the CVSS score for a finding
func (f Finding) WithCVSS(cvss float64) Finding {
	f.CVSS = cvss
	return f
}

// WithRemediation sets the remediation for a finding
func (f Finding) WithRemediation(remediation string) Finding {
	f.Remediation = remediation
	return f
}

// WithEvidence sets the evidence for a finding
func (f Finding) WithEvidence(evidence FindingEvidence) Finding {
	f.Evidence = evidence
	return f
}

// WithDetails adds details to the evidence
func (f Finding) WithDetails(details map[string]interface{}) Finding {
	if f.Evidence.Details == nil {
		f.Evidence.Details = make(map[string]interface{})
	}
	for k, v := range details {
		f.Evidence.Details[k] = v
	}
	return f
}

// WithReferences adds references to a finding
func (f Finding) WithReferences(refs ...string) Finding {
	f.References = append(f.References, refs...)
	return f
}

// WithCVEs adds CVEs to a finding
func (f Finding) WithCVEs(cves ...string) Finding {
	f.CVEs = append(f.CVEs, cves...)
	return f
}

// ============================================================================
// Severity Classification Helpers
// ============================================================================

// SeverityFromScore converts a CVSS score to severity
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// SeverityFromString parses a severity string
func SeverityFromString(s string) Severity {
	switch s {
	case "critical", "Critical", "CRITICAL":
		return SeverityCritical
	case "high", "High", "HIGH":
		return SeverityHigh
	case "medium", "Medium", "MEDIUM":
		return SeverityMedium
	case "low", "Low", "LOW":
		return SeverityLow
	case "info", "Info", "INFO", "informational", "Informational", "INFORMATIONAL":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// ============================================================================
// CVSS Calculation Helpers
// ============================================================================

// CVSSCalculator provides CVSS score calculation
type CVSSCalculator struct{}

// CalculateNetworkCVSS calculates CVSS score for network vulnerabilities
func (c *CVSSCalculator) CalculateNetworkCVSS(confidentiality, integrity, availability string) float64 {
	// Simplified CVSS 3.1 calculation
	// This is a basic implementation - use a full CVSS library for production

	baseScore := 0.0

	// Impact sub-score
	conf := c.getCIAValue(confidentiality)
	integ := c.getCIAValue(integrity)
	avail := c.getCIAValue(availability)

	impactSubScore := 1 - ((1 - conf) * (1 - integ) * (1 - avail))

	// Base score calculation (simplified)
	if impactSubScore <= 0 {
		return 0.0
	}

	// Network vector - most common for web/app vulnerabilities
	attackVector := 0.85       // Network
	attackComplexity := 0.77   // Low
	privilegesRequired := 0.85 // None
	userInteraction := 0.85    // None

	exploitability := 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction

	if impactSubScore > 0.915 {
		baseScore = 1.08 * (impactSubScore + exploitability)
	} else {
		baseScore = impactSubScore + exploitability
	}

	if baseScore > 10 {
		return 10.0
	}

	return baseScore
}

func (c *CVSSCalculator) getCIAValue(level string) float64 {
	switch level {
	case "high", "High", "HIGH", "H":
		return 0.56
	case "low", "Low", "LOW", "L":
		return 0.22
	default:
		return 0.0
	}
}

// CalculateExposureCVSS calculates CVSS for information exposure
func CalculateExposureCVSS() float64 {
	// Low severity exposure
	return 3.7
}

// CalculateConfigCVSS calculates CVSS for configuration issues
func CalculateConfigCVSS(severity string) float64 {
	switch severity {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.3
	case "low":
		return 3.7
	default:
		return 2.0
	}
}

// ============================================================================
// OWASP Mapping Helpers
// ============================================================================

// OWASPCategory represents OWASP Top 10 categories
type OWASPCategory string

const (
	OWASPBrokenAccessControl      OWASPCategory = "A01:2021-Broken Access Control"
	OWASPCryptoFailures           OWASPCategory = "A02:2021-Cryptographic Failures"
	OWASPInjection                OWASPCategory = "A03:2021-Injection"
	OWASPInsecureDesign           OWASPCategory = "A04:2021-Insecure Design"
	OWASPSecurityMisconfiguration OWASPCategory = "A05:2021-Security Misconfiguration"
	OWASPVulnerableComponents     OWASPCategory = "A06:2021-Vulnerable and Outdated Components"
	OWASPAuthFailures             OWASPCategory = "A07:2021-Identification and Authentication Failures"
	OWASPDataIntegrityFailures    OWASPCategory = "A08:2021-Software and Data Integrity Failures"
	OWASPSecurityLoggingFailures  OWASPCategory = "A09:2021-Security Logging and Monitoring Failures"
	OWASPServerSideRequestForgery OWASPCategory = "A10:2021-Server-Side Request Forgery (SSRF)"
)

// OWASPMapping maps finding categories to OWASP categories
var OWASPMapping = map[string]OWASPCategory{
	"sql-injection":             OWASPInjection,
	"command-injection":         OWASPInjection,
	"xss":                       OWASPInjection,
	"xxe":                       OWASPInjection,
	"authentication":            OWASPAuthFailures,
	"session-management":        OWASPAuthFailures,
	"access-control":            OWASPBrokenAccessControl,
	"insecure-direct-object":    OWASPBrokenAccessControl,
	"crypto":                    OWASPCryptoFailures,
	"tls":                       OWASPCryptoFailures,
	"configuration":             OWASPSecurityMisconfiguration,
	"security-headers":          OWASPSecurityMisconfiguration,
	"information-disclosure":    OWASPSecurityMisconfiguration,
	"outdated-software":         OWASPVulnerableComponents,
	"known-vulnerabilities":     OWASPVulnerableComponents,
	"logging":                   OWASPSecurityLoggingFailures,
	"monitoring":                OWASPSecurityLoggingFailures,
	"ssrf":                      OWASPServerSideRequestForgery,
	"open-redirect":             OWASPInsecureDesign,
	"business-logic":            OWASPInsecureDesign,
	"recon":                     OWASPSecurityMisconfiguration,
	"port-scan":                 OWASPSecurityMisconfiguration,
	"service-detection":         OWASPSecurityMisconfiguration,
	"dns-enumeration":           OWASPSecurityMisconfiguration,
	"subdomain-enumeration":     OWASPSecurityMisconfiguration,
	"technology-fingerprinting": OWASPSecurityMisconfiguration,
}

// GetOWASPCategory returns the OWASP category for a finding category
func GetOWASPCategory(category string) OWASPCategory {
	if owasp, ok := OWASPMapping[category]; ok {
		return owasp
	}
	return OWASPSecurityMisconfiguration // Default
}

// ============================================================================
// Evidence Formatting Helpers
// ============================================================================

// FormatHTTPRequest formats an HTTP request for evidence
func FormatHTTPRequest(method, url string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", method, url))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	if body != "" {
		sb.WriteString("\n")
		sb.WriteString(body)
	}
	return sb.String()
}

// FormatHTTPResponse formats an HTTP response for evidence
func FormatHTTPResponse(statusCode int, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d\n", statusCode))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	if body != "" {
		sb.WriteString("\n")
		if len(body) > 1000 {
			sb.WriteString(body[:1000])
			sb.WriteString("\n... [truncated]")
		} else {
			sb.WriteString(body)
		}
	}
	return sb.String()
}

// FormatPortScanResult formats a port scan result for evidence
func FormatPortScanResult(port int, open bool, service, banner string) string {
	status := "closed"
	if open {
		status = "open"
	}

	result := fmt.Sprintf("Port %d/%s - %s", port, service, status)
	if banner != "" {
		result += fmt.Sprintf(" | Banner: %s", strings.ReplaceAll(banner, "\n", "\\n"))
	}
	return result
}

// FormatDNSRecord formats a DNS record for evidence
func FormatDNSRecord(recordType, name, value string) string {
	return fmt.Sprintf("%s %s %s", recordType, name, value)
}

// TruncateString truncates a string to a maximum length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// SanitizeEvidence sanitizes evidence to remove sensitive data
func SanitizeEvidence(evidence string) string {
	// Remove common sensitive patterns
	patterns := []string{
		`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`,
		`(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+`,
		`(?i)(secret|token)\s*[=:]\s*\S+`,
		`(?i)(authorization|auth)\s*[=:]\s*[Bb]earer\s+\S+`,
		`[0-9a-f]{32,}`, // API keys, hashes
	}

	result := evidence
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		result = re.ReplaceAllString(result, "[REDACTED]")
	}

	return result
}

// CreateEvidenceDetails creates a map with common evidence details
func CreateEvidenceDetails(values ...interface{}) map[string]interface{} {
	details := make(map[string]interface{})
	for i := 0; i < len(values)-1; i += 2 {
		if key, ok := values[i].(string); ok {
			details[key] = values[i+1]
		}
	}
	return details
}

// ============================================================================
// Finding Aggregation Helpers
// ============================================================================

// AggregateFindings aggregates similar findings
func AggregateFindings(findings []Finding) []Finding {
	// Group findings by title and severity
	groups := make(map[string][]Finding)

	for _, f := range findings {
		key := fmt.Sprintf("%s:%s", f.Title, f.Severity)
		groups[key] = append(groups[key], f)
	}

	var aggregated []Finding
	for _, group := range groups {
		if len(group) == 1 {
			aggregated = append(aggregated, group[0])
			continue
		}

		// Aggregate multiple findings into one
		base := group[0]

		// Collect all targets
		var targets []string
		for _, f := range group {
			if f.Target != "" {
				targets = append(targets, f.Target)
			}
		}

		if len(targets) > 0 {
			base.Description = fmt.Sprintf("%s (Found on %d targets: %s)",
				base.Description, len(targets), strings.Join(targets, ", "))
		}

		aggregated = append(aggregated, base)
	}

	return aggregated
}

// SortFindings sorts findings by severity (highest first)
func SortFindings(findings []Finding) []Finding {
	// Simple bubble sort for now - use sort.Slice for production
	for i := 0; i < len(findings)-1; i++ {
		for j := i + 1; j < len(findings); j++ {
			if findings[i].Severity.Score() < findings[j].Severity.Score() {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
	return findings
}

// FilterFindingsBySeverity filters findings by minimum severity
func FilterFindingsBySeverity(findings []Finding, minSeverity Severity) []Finding {
	minScore := minSeverity.Score()
	var filtered []Finding

	for _, f := range findings {
		if f.Severity.Score() >= minScore {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// CountFindingsBySeverity counts findings by severity
func CountFindingsBySeverity(findings []Finding) FindingSummary {
	summary := FindingSummary{}
	for _, f := range findings {
		summary.Add(f.Severity)
	}
	return summary
}
