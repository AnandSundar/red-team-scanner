// Package payloads provides threat intelligence data, CVE mappings, and indicator patterns
package payloads

import (
	"regexp"
	"strings"
)

// ============================================================================
// CVE Data Structures
// ============================================================================

// CVEEntry represents a known CVE entry with metadata
type CVEEntry struct {
	ID          string
	Severity    string  // Critical, High, Medium, Low
	CVSS        float64 // CVSS v3 score
	Description string
	CPE         []string // Affected CPE patterns
	References  []string
	KEV         bool    // Known Exploited Vulnerability (CISA KEV)
	EPSS        float64 // Exploit Prediction Scoring System score
}

// TechnologyVersion represents a detected technology with version
type TechnologyVersion struct {
	Name    string
	Version string
	Vendor  string
}

// ============================================================================
// Known CVE Database
// ============================================================================

// KnownCVEs contains a curated list of high-impact CVEs mapped to technologies
var KnownCVEs = map[string][]CVEEntry{
	"apache": {
		{
			ID:          "CVE-2021-41773",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49",
			CPE:         []string{"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
			KEV:         true,
			EPSS:        0.97,
		},
		{
			ID:          "CVE-2021-42013",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Path traversal in Apache HTTP Server 2.4.49 and 2.4.50",
			CPE:         []string{"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
			KEV:         true,
			EPSS:        0.95,
		},
		{
			ID:          "CVE-2022-31813",
			Severity:    "High",
			CVSS:        8.2,
			Description: "IP address spoofing in mod_remoteip of Apache HTTP Server",
			CPE:         []string{"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-31813"},
			KEV:         false,
			EPSS:        0.15,
		},
		{
			ID:          "CVE-2022-23943",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Out-of-bounds write in mod_sed of Apache HTTP Server",
			CPE:         []string{"cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-23943"},
			KEV:         false,
			EPSS:        0.12,
		},
	},
	"nginx": {
		{
			ID:          "CVE-2021-23017",
			Severity:    "Critical",
			CVSS:        9.4,
			Description: "DNS resolver vulnerability in nginx 0.6.18-1.20.0",
			CPE:         []string{"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
			KEV:         false,
			EPSS:        0.08,
		},
		{
			ID:          "CVE-2022-41741",
			Severity:    "High",
			CVSS:        7.5,
			Description: "Memory corruption in ngx_http_mp4_module",
			CPE:         []string{"cpe:2.3:a:nginx:nginx:1.23.0:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-41741"},
			KEV:         false,
			EPSS:        0.05,
		},
	},
	"php": {
		{
			ID:          "CVE-2024-4577",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "PHP CGI argument injection vulnerability affecting PHP 8.1.* before 8.1.29",
			CPE:         []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4577"},
			KEV:         true,
			EPSS:        0.99,
		},
		{
			ID:          "CVE-2023-3824",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Buffer overflow in phar parsing in PHP",
			CPE:         []string{"cpe:2.3:a:php:php:8.0.29:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-3824"},
			KEV:         false,
			EPSS:        0.25,
		},
		{
			ID:          "CVE-2019-11043",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Remote code execution in PHP-FPM under certain configurations",
			CPE:         []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-11043"},
			KEV:         true,
			EPSS:        0.85,
		},
	},
	"openssl": {
		{
			ID:          "CVE-2023-0286",
			Severity:    "High",
			CVSS:        7.4,
			Description: "X.400 address type confusion in OpenSSL 3.0.0-3.0.7",
			CPE:         []string{"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-0286"},
			KEV:         false,
			EPSS:        0.10,
		},
		{
			ID:          "CVE-2022-3602",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "X.509 Email Address buffer overflow in OpenSSL 3.0.0-3.0.6",
			CPE:         []string{"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-3602"},
			KEV:         false,
			EPSS:        0.45,
		},
	},
	"log4j": {
		{
			ID:          "CVE-2021-44228",
			Severity:    "Critical",
			CVSS:        10.0,
			Description: "Log4Shell - Remote code execution in Log4j 2.0-beta9 to 2.14.1",
			CPE:         []string{"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			KEV:         true,
			EPSS:        0.99,
		},
		{
			ID:          "CVE-2021-45046",
			Severity:    "Critical",
			CVSS:        9.0,
			Description: "Additional fix for Log4Shell in Log4j 2.15.0",
			CPE:         []string{"cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-45046"},
			KEV:         true,
			EPSS:        0.98,
		},
	},
	"wordpress": {
		{
			ID:          "CVE-2024-10400",
			Severity:    "High",
			CVSS:        8.1,
			Description: "SQL injection in WordPress plugins (various)",
			CPE:         []string{"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-10400"},
			KEV:         false,
			EPSS:        0.15,
		},
		{
			ID:          "CVE-2023-6553",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Unauthenticated remote code execution in Backup Migration plugin",
			CPE:         []string{"cpe:2.3:a:backup_migration_project:backup_migration:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-6553"},
			KEV:         true,
			EPSS:        0.95,
		},
	},
	"jenkins": {
		{
			ID:          "CVE-2024-23897",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Arbitrary file read vulnerability in Jenkins CLI",
			CPE:         []string{"cpe:2.3:a:jenkins:jenkins:*:*:*:*:lts:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-23897"},
			KEV:         true,
			EPSS:        0.92,
		},
	},
	"drupal": {
		{
			ID:          "CVE-2018-7600",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Drupalgeddon2 - Remote code execution in Drupal < 7.58, < 8.3.9, < 8.4.6, < 8.5.1",
			CPE:         []string{"cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
			KEV:         true,
			EPSS:        0.98,
		},
		{
			ID:          "CVE-2019-6340",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Remote code execution in Drupal RESTful Web Services",
			CPE:         []string{"cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-6340"},
			KEV:         true,
			EPSS:        0.85,
		},
	},
	"struts": {
		{
			ID:          "CVE-2017-5638",
			Severity:    "Critical",
			CVSS:        10.0,
			Description: "Remote code execution in Apache Struts 2 through 2.3.32 and 2.5.x through 2.5.10.1",
			CPE:         []string{"cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-5638"},
			KEV:         true,
			EPSS:        0.99,
		},
	},
	"tomcat": {
		{
			ID:          "CVE-2020-1938",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Ghostcat - AJP connector vulnerability in Tomcat",
			CPE:         []string{"cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-1938"},
			KEV:         true,
			EPSS:        0.88,
		},
	},
	"redis": {
		{
			ID:          "CVE-2023-36824",
			Severity:    "High",
			CVSS:        7.5,
			Description: "Heap overflow in Redis EXEC command",
			CPE:         []string{"cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-36824"},
			KEV:         false,
			EPSS:        0.20,
		},
	},
	"mysql": {
		{
			ID:          "CVE-2023-21963",
			Severity:    "High",
			CVSS:        7.1,
			Description: "Vulnerability in MySQL Server",
			CPE:         []string{"cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-21963"},
			KEV:         false,
			EPSS:        0.15,
		},
	},
	"postgresql": {
		{
			ID:          "CVE-2023-39417",
			Severity:    "High",
			CVSS:        8.0,
			Description: "SQL injection in PostgreSQL extensions",
			CPE:         []string{"cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-39417"},
			KEV:         false,
			EPSS:        0.12,
		},
	},
	"mongodb": {
		{
			ID:          "CVE-2021-20329",
			Severity:    "High",
			CVSS:        7.5,
			Description: "Integer overflow in MongoDB Server",
			CPE:         []string{"cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-20329"},
			KEV:         false,
			EPSS:        0.10,
		},
	},
	"docker": {
		{
			ID:          "CVE-2024-21626",
			Severity:    "High",
			CVSS:        8.6,
			Description: "runc container breakout vulnerability",
			CPE:         []string{"cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-21626"},
			KEV:         false,
			EPSS:        0.35,
		},
	},
	"kubernetes": {
		{
			ID:          "CVE-2023-5528",
			Severity:    "Critical",
			CVSS:        9.8,
			Description: "Arbitrary command execution in Kubernetes",
			CPE:         []string{"cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-5528"},
			KEV:         false,
			EPSS:        0.25,
		},
	},
}

// CISA_KEV_CVEs is a list of CVEs in CISA's Known Exploited Vulnerabilities Catalog
var CISA_KEV_CVEs = map[string]bool{
	"CVE-2021-44228": true, // Log4Shell
	"CVE-2021-45046": true, // Log4Shell follow-up
	"CVE-2021-41773": true, // Apache path traversal
	"CVE-2021-42013": true, // Apache path traversal
	"CVE-2019-11043": true, // PHP-FPM RCE
	"CVE-2017-5638":  true, // Struts2 RCE
	"CVE-2018-7600":  true, // Drupalgeddon2
	"CVE-2020-1938":  true, // Ghostcat
	"CVE-2019-6340":  true, // Drupal REST RCE
	"CVE-2024-4577":  true, // PHP CGI
	"CVE-2023-6553":  true, // WordPress Backup Migration
	"CVE-2024-23897": true, // Jenkins CLI
	"CVE-2024-21762": true, // Fortinet SSL VPN
	"CVE-2023-4966":  true, // Citrix Bleed
	"CVE-2023-34362": true, // MOVEit Transfer
	"CVE-2023-2868":  true, // Barracuda ESG
	"CVE-2023-27350": true, // PaperCut MF/NG
}

// ============================================================================
// Technology Detection Patterns
// ============================================================================

// TechnologyPatterns maps technology names to detection regexes
type TechnologyPattern struct {
	Name         string
	VersionRegex *regexp.Regexp
	Vendor       string
}

// CommonTechnologyPatterns contains regex patterns for version extraction
var CommonTechnologyPatterns = []TechnologyPattern{
	{
		Name:         "Apache",
		VersionRegex: regexp.MustCompile(`(?i)apache[/\s-]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "Apache Software Foundation",
	},
	{
		Name:         "nginx",
		VersionRegex: regexp.MustCompile(`(?i)nginx[/\s]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "F5",
	},
	{
		Name:         "PHP",
		VersionRegex: regexp.MustCompile(`(?i)php[/\s]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "PHP Group",
	},
	{
		Name:         "OpenSSL",
		VersionRegex: regexp.MustCompile(`(?i)openssl[/\s]?(\d+\.\d+(?:\.\d+)?[a-z]?)`),
		Vendor:       "OpenSSL Project",
	},
	{
		Name:         "WordPress",
		VersionRegex: regexp.MustCompile(`(?i)wordpress[/\s]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "WordPress Foundation",
	},
	{
		Name:         "Drupal",
		VersionRegex: regexp.MustCompile(`(?i)drupal[/\s]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "Drupal Association",
	},
	{
		Name:         "Jenkins",
		VersionRegex: regexp.MustCompile(`(?i)jenkins[/\s]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "CloudBees",
	},
	{
		Name:         "Tomcat",
		VersionRegex: regexp.MustCompile(`(?i)tomcat[/\s-]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "Apache Software Foundation",
	},
	{
		Name:         "MySQL",
		VersionRegex: regexp.MustCompile(`(?i)mysql[/\s]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "Oracle",
	},
	{
		Name:         "PostgreSQL",
		VersionRegex: regexp.MustCompile(`(?i)postgresql[/\s]?(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "PostgreSQL Global Development Group",
	},
}

// ============================================================================
// Malicious Certificate Fingerprints
// ============================================================================

// KnownMaliciousCerts contains SHA256 fingerprints of known malicious certificates
var KnownMaliciousCerts = map[string]string{
	// Example format - in production, these would be real malicious cert fingerprints
	"de28f4a4ffe6b92fa3fc542da3c3e2bf5e2f5d01": "Example malicious cert - replace with real data",
}

// SuspiciousCertificatePatterns contains patterns for suspicious cert details
var SuspiciousCertificatePatterns = []string{
	"test",
	"fake",
	"malicious",
	"hacked",
	"evil",
}

// ============================================================================
// Suspicious Port Configurations
// ============================================================================

// SuspiciousPortConfigs maps ports to security concerns
type PortSecurityInfo struct {
	Port        int
	Service     string
	RiskLevel   string // critical, high, medium, low
	Description string
	External    bool // True if exposure to internet is concerning
}

// SuspiciousPorts contains ports that warrant security attention when exposed
var SuspiciousPorts = []PortSecurityInfo{
	{Port: 21, Service: "FTP", RiskLevel: "high", Description: "FTP transmits credentials in cleartext", External: true},
	{Port: 23, Service: "Telnet", RiskLevel: "critical", Description: "Telnet transmits all data in cleartext including credentials", External: true},
	{Port: 25, Service: "SMTP", RiskLevel: "medium", Description: "Open SMTP relay may enable spam/phishing", External: true},
	{Port: 53, Service: "DNS", RiskLevel: "medium", Description: "Open DNS resolver can be used for amplification attacks", External: true},
	{Port: 110, Service: "POP3", RiskLevel: "high", Description: "POP3 without TLS exposes credentials", External: true},
	{Port: 143, Service: "IMAP", RiskLevel: "high", Description: "IMAP without TLS exposes credentials", External: true},
	{Port: 161, Service: "SNMP", RiskLevel: "high", Description: "SNMP can expose system information and configuration", External: true},
	{Port: 389, Service: "LDAP", RiskLevel: "high", Description: "LDAP without TLS exposes credentials and directory data", External: true},
	{Port: 445, Service: "SMB", RiskLevel: "critical", Description: "SMB exposure enables file sharing attacks and ransomware", External: true},
	{Port: 1433, Service: "MSSQL", RiskLevel: "critical", Description: "Exposed MSSQL database", External: true},
	{Port: 1521, Service: "Oracle", RiskLevel: "critical", Description: "Exposed Oracle database", External: true},
	{Port: 2049, Service: "NFS", RiskLevel: "high", Description: "Exposed NFS shares", External: true},
	{Port: 2375, Service: "Docker", RiskLevel: "critical", Description: "Docker daemon API allows remote code execution", External: true},
	{Port: 2376, Service: "Docker-TLS", RiskLevel: "medium", Description: "Docker daemon with TLS - verify certificate auth", External: false},
	{Port: 3306, Service: "MySQL", RiskLevel: "critical", Description: "Exposed MySQL database", External: true},
	{Port: 3389, Service: "RDP", RiskLevel: "high", Description: "Exposed Remote Desktop Protocol", External: true},
	{Port: 5432, Service: "PostgreSQL", RiskLevel: "critical", Description: "Exposed PostgreSQL database", External: true},
	{Port: 6379, Service: "Redis", RiskLevel: "critical", Description: "Exposed Redis database - often has no auth", External: true},
	{Port: 27017, Service: "MongoDB", RiskLevel: "critical", Description: "Exposed MongoDB database", External: true},
	{Port: 27018, Service: "MongoDB-Shard", RiskLevel: "critical", Description: "Exposed MongoDB sharding service", External: true},
	{Port: 9200, Service: "Elasticsearch", RiskLevel: "critical", Description: "Exposed Elasticsearch - often has no auth", External: true},
	{Port: 9300, Service: "Elasticsearch-Transport", RiskLevel: "high", Description: "Exposed Elasticsearch transport", External: true},
	{Port: 11211, Service: "Memcached", RiskLevel: "critical", Description: "Exposed Memcached - often has no auth", External: true},
	{Port: 5984, Service: "CouchDB", RiskLevel: "high", Description: "Exposed CouchDB", External: true},
	{Port: 50070, Service: "Hadoop-NameNode", RiskLevel: "critical", Description: "Exposed Hadoop NameNode UI", External: true},
	{Port: 50075, Service: "Hadoop-DataNode", RiskLevel: "high", Description: "Exposed Hadoop DataNode", External: true},
	{Port: 8080, Service: "HTTP-Alt", RiskLevel: "low", Description: "Alternative HTTP port", External: false},
	{Port: 8443, Service: "HTTPS-Alt", RiskLevel: "low", Description: "Alternative HTTPS port", External: false},
	{Port: 8888, Service: "HTTP-Alt", RiskLevel: "medium", Description: "Alternative HTTP port - often used for admin interfaces", External: false},
	{Port: 9000, Service: "PHP-FPM", RiskLevel: "high", Description: "PHP-FPM fastcgi - can be exploited if misconfigured", External: true},
	{Port: 9999, Service: "Admin", RiskLevel: "high", Description: "Often used for admin interfaces - verify authentication", External: false},
	{Port: 10000, Service: "Webmin", RiskLevel: "high", Description: "Webmin system administration tool", External: true},
	{Port: 10250, Service: "Kubelet", RiskLevel: "critical", Description: "Kubernetes Kubelet API - may expose cluster control", External: true},
	{Port: 10255, Service: "Kubelet-ReadOnly", RiskLevel: "high", Description: "Kubernetes Kubelet read-only port", External: true},
	{Port: 6443, Service: "Kubernetes-API", RiskLevel: "critical", Description: "Kubernetes API server - verify authentication", External: true},
}

// GetPortSecurityInfo returns security info for a port
func GetPortSecurityInfo(port int) *PortSecurityInfo {
	for _, info := range SuspiciousPorts {
		if info.Port == port {
			return &info
		}
	}
	return nil
}

// ============================================================================
// Threat Intelligence Indicator Patterns
// ============================================================================

// SuspiciousPatterns contains regex patterns for suspicious content
type SuspiciousPattern struct {
	Pattern     string
	Name        string
	Severity    string
	Category    string
	Description string
}

// SuspiciousPatterns contains patterns for threat detection
var SuspiciousPatterns = []SuspiciousPattern{
	{
		Pattern:     `(?i)hack(ed|er|ing)`,
		Name:        "Hacking Reference",
		Severity:    "medium",
		Category:    "suspicious-content",
		Description: "Content contains hacking-related terms",
	},
	{
		Pattern:     `(?i)(shell|webshell|c99|r57|china|b374k)`,
		Name:        "Potential Webshell",
		Severity:    "critical",
		Category:    "malware",
		Description: "Potential webshell or backdoor reference detected",
	},
	{
		Pattern:     `(?i)(eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec)`,
		Name:        "Dangerous Function Call",
		Severity:    "high",
		Category:    "code-execution",
		Description: "Dangerous PHP function calls detected",
	},
	{
		Pattern:     `(?i)(base64_decode|str_rot13|gzinflate|strrev)\s*\(`,
		Name:        "Obfuscation Pattern",
		Severity:    "high",
		Category:    "obfuscation",
		Description: "Common obfuscation function calls detected",
	},
	{
		Pattern:     `(?i)(crypt|ransom|encrypt.*file|decrypt.*file)`,
		Name:        "Ransomware Pattern",
		Severity:    "critical",
		Category:    "ransomware",
		Description: "Potential ransomware-related content",
	},
	{
		Pattern:     `(?i)(bitcoin|btc|monero|wallet).{0,50}(pay|send|transfer)`,
		Name:        "Cryptocurrency Payment Request",
		Severity:    "medium",
		Category:    "cryptocurrency",
		Description: "Cryptocurrency payment reference detected",
	},
	{
		Pattern:     `(?i)(sqlmap|nikto|nmap|nessus|burp|metasploit)`,
		Name:        "Security Tool Reference",
		Severity:    "low",
		Category:    "security-tools",
		Description: "Security testing tool mentioned",
	},
}

// MatchSuspiciousPatterns checks content against suspicious patterns
func MatchSuspiciousPatterns(content string) []SuspiciousPattern {
	matches := []SuspiciousPattern{}
	for _, pattern := range SuspiciousPatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, content)
		if matched {
			matches = append(matches, pattern)
		}
	}
	return matches
}

// ============================================================================
// Technology-to-CVE Mapping Functions
// ============================================================================

// ExtractTechnologyVersion attempts to extract technology and version from a string
func ExtractTechnologyVersion(text string) *TechnologyVersion {
	for _, pattern := range CommonTechnologyPatterns {
		matches := pattern.VersionRegex.FindStringSubmatch(text)
		if len(matches) >= 2 {
			return &TechnologyVersion{
				Name:    pattern.Name,
				Version: matches[1],
				Vendor:  pattern.Vendor,
			}
		}
	}
	return nil
}

// MatchCVEsForTechnology finds CVEs matching a technology and version
func MatchCVEsForTechnology(name, version string) []CVEEntry {
	matches := []CVEEntry{}
	nameLower := strings.ToLower(name)

	// Try exact technology match
	if cves, ok := KnownCVEs[nameLower]; ok {
		matches = append(matches, cves...)
	}

	// Also try matching against common aliases
	aliases := map[string][]string{
		"apache http server": {"apache"},
		"apache httpd":       {"apache"},
		"httpd":              {"apache"},
		"php-fpm":            {"php"},
	}

	if aliasedNames, ok := aliases[nameLower]; ok {
		for _, aliasedName := range aliasedNames {
			if cves, ok := KnownCVEs[aliasedName]; ok {
				matches = append(matches, cves...)
			}
		}
	}

	return matches
}

// IsKEV checks if a CVE is in the Known Exploited Vulnerabilities catalog
func IsKEV(cveID string) bool {
	return CISA_KEV_CVEs[cveID]
}

// SeverityToScore converts severity string to numeric score
func SeverityToScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 4.0
	case "high":
		return 3.0
	case "medium":
		return 2.0
	case "low":
		return 1.0
	default:
		return 0.0
	}
}

// GetCVESeverityFromScore determines severity from CVSS score
func GetCVESeverityFromScore(score float64) string {
	if score >= 9.0 {
		return "Critical"
	} else if score >= 7.0 {
		return "High"
	} else if score >= 4.0 {
		return "Medium"
	} else if score > 0 {
		return "Low"
	}
	return "Unknown"
}

// VersionInRange checks if a version is within a vulnerable range (simplified)
func VersionInRange(version, minVersion, maxVersion string) bool {
	// Simplified version comparison - in production would use proper semver library
	// This is a placeholder for actual version range checking
	return true // Assume vulnerable if tech matches (conservative approach)
}

// ============================================================================
// AbuseIPDB Categories
// ============================================================================

// AbuseIPDBCategories maps category IDs to descriptions
var AbuseIPDBCategories = map[int]string{
	1:  "DNS Compromise",
	2:  "DNS Poisoning",
	3:  "Fraud Orders",
	4:  "DDoS Attack",
	5:  "FTP Brute-Force",
	6:  "Ping of Death",
	7:  "Phishing",
	8:  "Fraud VoIP",
	9:  "Open Proxy",
	10: "Web Spam",
	11: "Email Spam",
	12: "Blog Spam",
	13: "VPN IP",
	14: "Port Scan",
	15: "Hacking",
	16: "SQL Injection",
	17: "Spoofing",
	18: "Brute-Force",
	19: "Bad Web Bot",
	20: "Exploited Host",
	21: "Web App Attack",
	22: "SSH",
	23: "IoT Targeted",
}

// GetAbuseIPDBCategory returns the category description for a category ID
func GetAbuseIPDBCategory(id int) string {
	if desc, ok := AbuseIPDBCategories[id]; ok {
		return desc
	}
	return "Unknown"
}

// HighRiskAbuseCategories are categories that indicate high-risk IPs
var HighRiskAbuseCategories = []int{
	4,  // DDoS Attack
	7,  // Phishing
	15, // Hacking
	16, // SQL Injection
	18, // Brute-Force
	20, // Exploited Host
	21, // Web App Attack
	23, // IoT Targeted
}

// IsHighRiskCategory checks if a category indicates high risk
func IsHighRiskCategory(categoryID int) bool {
	for _, id := range HighRiskAbuseCategories {
		if id == categoryID {
			return true
		}
	}
	return false
}
