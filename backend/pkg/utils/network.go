// Package utils provides network utilities for security scanning
package utils

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Connection Types and Constants
// ============================================================================

// TCPConnectionResult represents the result of a TCP connection attempt
type TCPConnectionResult struct {
	Port      int           `json:"port"`
	Open      bool          `json:"open"`
	Banner    string        `json:"banner,omitempty"`
	Service   string        `json:"service,omitempty"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl,omitempty"`
	Target string `json:"target,omitempty"`
}

// DNSQueryResult contains the result of a DNS query
type DNSQueryResult struct {
	Records  []DNSRecord   `json:"records"`
	Error    string        `json:"error,omitempty"`
	Server   string        `json:"server"`
	Duration time.Duration `json:"duration"`
}

// PortScanConfig contains configuration for port scanning
type PortScanConfig struct {
	Timeout       time.Duration
	Concurrency   int
	BannerGrab    bool
	BannerMaxSize int
}

// DefaultPortScanConfig returns default port scanning configuration
func DefaultPortScanConfig() PortScanConfig {
	return PortScanConfig{
		Timeout:       5 * time.Second,
		Concurrency:   200,
		BannerGrab:    true,
		BannerMaxSize: 512,
	}
}

// ============================================================================
// TCP Connection Helpers
// ============================================================================

// TCPConnect attempts to connect to a TCP port with timeout
func TCPConnect(ctx context.Context, host string, port int, timeout time.Duration) (*TCPConnectionResult, error) {
	result := &TCPConnectionResult{
		Port:      port,
		Timestamp: time.Now(),
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	result.Duration = time.Since(start)

	if err != nil {
		result.Open = false
		result.Error = err.Error()
		return result, nil
	}
	defer conn.Close()

	result.Open = true

	// Grab banner if requested
	if timeout > 0 {
		banner, err := ReadBanner(conn, timeout, 512)
		if err == nil && banner != "" {
			result.Banner = banner
			result.Service = IdentifyService(port, banner)
		}
	}

	return result, nil
}

// ReadBanner reads the banner from a connection
func ReadBanner(conn net.Conn, timeout time.Duration, maxSize int) (string, error) {
	if maxSize == 0 {
		maxSize = 512
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, maxSize)
	n, err := conn.Read(buffer)

	if err != nil && err != io.EOF {
		return "", err
	}

	// Clean up the banner (remove non-printable characters)
	banner := string(buffer[:n])
	banner = CleanBanner(banner)

	return banner, nil
}

// CleanBanner removes non-printable characters from a banner
func CleanBanner(banner string) string {
	var cleaned strings.Builder
	for _, r := range banner {
		if r >= 32 && r < 127 || r == '\n' || r == '\t' {
			cleaned.WriteRune(r)
		}
	}
	return strings.TrimSpace(cleaned.String())
}

// IdentifyService identifies the service based on port and banner
func IdentifyService(port int, banner string) string {
	// First check known port mappings
	service := GetServiceForPort(port)
	if service != "unknown" {
		return service
	}

	// Try to identify from banner
	bannerLower := strings.ToLower(banner)

	servicePatterns := map[string][]string{
		"SSH":        {"ssh", "openssh", "libssh"},
		"HTTP":       {"http", "html", "<!doctype", "<!DOCTYPE"},
		"FTP":        {"ftp", "vsftpd", "proftpd", "pure-ftpd"},
		"SMTP":       {"smtp", "esmtp", "postfix", "sendmail", "exim"},
		"POP3":       {"pop3", "pop"},
		"IMAP":       {"imap", "imap4"},
		"Telnet":     {"telnet"},
		"MySQL":      {"mysql", "mariadb"},
		"PostgreSQL": {"postgresql"},
		"Redis":      {"redis"},
		"MongoDB":    {"mongodb"},
		"RDP":        {"rdp", "remote desktop"},
		"VNC":        {"vnc", "rfb"},
		"Docker":     {"docker"},
	}

	for serviceName, patterns := range servicePatterns {
		for _, pattern := range patterns {
			if strings.Contains(bannerLower, pattern) {
				return serviceName
			}
		}
	}

	return "unknown"
}

// GetServiceForPort returns the common service name for a port
func GetServiceForPort(port int) string {
	commonPorts := map[int]string{
		20:    "FTP-Data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		119:   "NNTP",
		123:   "NTP",
		135:   "MS-RPC",
		139:   "NetBIOS",
		143:   "IMAP",
		161:   "SNMP",
		162:   "SNMP-Trap",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		514:   "Syslog",
		587:   "SMTP-Submit",
		636:   "LDAPS",
		873:   "RSYNC",
		989:   "FTPS-Data",
		990:   "FTPS",
		993:   "IMAPS",
		995:   "POP3S",
		1080:  "SOCKS",
		1433:  "MSSQL",
		1521:  "Oracle",
		1723:  "PPTP",
		2049:  "NFS",
		2375:  "Docker",
		2376:  "Docker-TLS",
		3000:  "Grafana",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		5984:  "CouchDB",
		6379:  "Redis",
		6443:  "K8s-API",
		8000:  "HTTP-Alt",
		8080:  "HTTP-Proxy",
		8443:  "HTTPS-Alt",
		9200:  "Elasticsearch",
		9300:  "ES-Transport",
		9418:  "Git",
		27017: "MongoDB",
		27018: "MongoDB-Shard",
		27019: "MongoDB-Config",
	}

	if service, ok := commonPorts[port]; ok {
		return service
	}
	return "unknown"
}

// ============================================================================
// Port Scanning
// ============================================================================

// ScanPorts performs a TCP port scan on a target
func ScanPorts(ctx context.Context, host string, ports []int, config PortScanConfig) ([]TCPConnectionResult, error) {
	if config.Concurrency == 0 {
		config.Concurrency = 200
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	results := make([]TCPConnectionResult, 0, len(ports))
	resultsMu := sync.Mutex{}

	// Create work channel
	work := make(chan int, len(ports))
	for _, port := range ports {
		work <- port
	}
	close(work)

	// Use WaitGroup to wait for all workers
	var wg sync.WaitGroup

	// Start workers
	numWorkers := config.Concurrency
	if numWorkers > len(ports) {
		numWorkers = len(ports)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case port, ok := <-work:
					if !ok {
						return
					}

					result, err := TCPConnect(ctx, host, port, config.Timeout)
					if err != nil {
						continue
					}

					resultsMu.Lock()
					results = append(results, *result)
					resultsMu.Unlock()
				}
			}
		}()
	}

	// Wait for all workers to complete
	wg.Wait()

	return results, nil
}

// ScanPortRange scans a range of ports
func ScanPortRange(ctx context.Context, host string, startPort, endPort int, config PortScanConfig) ([]TCPConnectionResult, error) {
	if startPort < 1 {
		startPort = 1
	}
	if endPort > 65535 {
		endPort = 65535
	}

	ports := make([]int, 0, endPort-startPort+1)
	for i := startPort; i <= endPort; i++ {
		ports = append(ports, i)
	}

	return ScanPorts(ctx, host, ports, config)
}

// ============================================================================
// DNS Resolution
// ============================================================================

// DNSResolver provides DNS resolution functionality
type DNSResolver struct {
	servers []string
	timeout time.Duration
}

// NewDNSResolver creates a new DNS resolver with custom servers
func NewDNSResolver(servers []string, timeout time.Duration) *DNSResolver {
	if len(servers) == 0 {
		servers = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &DNSResolver{
		servers: servers,
		timeout: timeout,
	}
}

// DefaultResolver returns a resolver with default settings
func DefaultResolver() *DNSResolver {
	return NewDNSResolver(nil, 5*time.Second)
}

// LookupA performs an A record lookup
func (r *DNSResolver) LookupA(ctx context.Context, hostname string) (*DNSQueryResult, error) {
	return r.lookupWithType(ctx, hostname, "A")
}

// LookupAAAA performs an AAAA record lookup
func (r *DNSResolver) LookupAAAA(ctx context.Context, hostname string) (*DNSQueryResult, error) {
	return r.lookupWithType(ctx, hostname, "AAAA")
}

// LookupMX performs an MX record lookup
func (r *DNSResolver) LookupMX(ctx context.Context, hostname string) (*DNSQueryResult, error) {
	result := &DNSQueryResult{Server: r.servers[0]}

	start := time.Now()
	records, err := net.LookupMX(hostname)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	for _, mx := range records {
		result.Records = append(result.Records, DNSRecord{
			Type:   "MX",
			Name:   hostname,
			Value:  mx.Host,
			Target: mx.Host,
		})
	}

	return result, nil
}

// LookupNS performs an NS record lookup
func (r *DNSResolver) LookupNS(ctx context.Context, hostname string) (*DNSQueryResult, error) {
	result := &DNSQueryResult{Server: r.servers[0]}

	start := time.Now()
	records, err := net.LookupNS(hostname)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	for _, ns := range records {
		result.Records = append(result.Records, DNSRecord{
			Type:   "NS",
			Name:   hostname,
			Value:  ns.Host,
			Target: ns.Host,
		})
	}

	return result, nil
}

// LookupTXT performs a TXT record lookup
func (r *DNSResolver) LookupTXT(ctx context.Context, hostname string) (*DNSQueryResult, error) {
	result := &DNSQueryResult{Server: r.servers[0]}

	start := time.Now()
	records, err := net.LookupTXT(hostname)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	for _, txt := range records {
		result.Records = append(result.Records, DNSRecord{
			Type:  "TXT",
			Name:  hostname,
			Value: txt,
		})
	}

	return result, nil
}

// LookupCNAME performs a CNAME record lookup
func (r *DNSResolver) LookupCNAME(ctx context.Context, hostname string) (*DNSQueryResult, error) {
	result := &DNSQueryResult{Server: r.servers[0]}

	start := time.Now()
	cname, err := net.LookupCNAME(hostname)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if cname != "" && cname != hostname+"." && cname != hostname {
		result.Records = append(result.Records, DNSRecord{
			Type:   "CNAME",
			Name:   hostname,
			Value:  strings.TrimSuffix(cname, "."),
			Target: strings.TrimSuffix(cname, "."),
		})
	}

	return result, nil
}

// LookupPTR performs a PTR (reverse DNS) lookup
func (r *DNSResolver) LookupPTR(ctx context.Context, ip string) (*DNSQueryResult, error) {
	result := &DNSQueryResult{Server: r.servers[0]}

	start := time.Now()
	names, err := net.LookupAddr(ip)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	for _, name := range names {
		result.Records = append(result.Records, DNSRecord{
			Type:  "PTR",
			Name:  ip,
			Value: strings.TrimSuffix(name, "."),
		})
	}

	return result, nil
}

// LookupHost performs a host lookup (A and AAAA)
func (r *DNSResolver) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	return net.LookupHost(hostname)
}

// lookupWithType performs a DNS lookup with a specific type
func (r *DNSResolver) lookupWithType(ctx context.Context, hostname, recordType string) (*DNSQueryResult, error) {
	result := &DNSQueryResult{Server: r.servers[0]}

	start := time.Now()
	ips, err := net.LookupIP(hostname)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	for _, ip := range ips {
		record := DNSRecord{
			Type:  recordType,
			Name:  hostname,
			Value: ip.String(),
		}
		if ip.To4() != nil {
			record.Type = "A"
		} else {
			record.Type = "AAAA"
		}
		result.Records = append(result.Records, record)
	}

	return result, nil
}

// GetAllRecords retrieves all common DNS record types
func (r *DNSResolver) GetAllRecords(ctx context.Context, hostname string) map[string]*DNSQueryResult {
	results := make(map[string]*DNSQueryResult)

	var wg sync.WaitGroup
	var mu sync.Mutex

	queries := []struct {
		name string
		fn   func(context.Context, string) (*DNSQueryResult, error)
	}{
		{"A", r.LookupA},
		{"AAAA", r.LookupAAAA},
		{"MX", r.LookupMX},
		{"NS", r.LookupNS},
		{"TXT", r.LookupTXT},
		{"CNAME", r.LookupCNAME},
	}

	for _, q := range queries {
		wg.Add(1)
		go func(name string, fn func(context.Context, string) (*DNSQueryResult, error)) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
				result, err := fn(ctx, hostname)
				if err == nil {
					mu.Lock()
					results[name] = result
					mu.Unlock()
				}
			}
		}(q.name, q.fn)
	}

	wg.Wait()
	return results
}

// ============================================================================
// IP Validation and CIDR Parsing
// ============================================================================

// IsValidIP checks if a string is a valid IP address
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidIPv4 checks if a string is a valid IPv4 address
func IsValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// IsValidIPv6 checks if a string is a valid IPv6 address
func IsValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// IsPrivateIP checks if an IP address is private
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// ParseCIDR parses a CIDR notation and returns all IPs
func ParseCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for IPv4
	if len(ips) > 2 && ip.To4() != nil {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

// incrementIP increments an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetHostFromTarget extracts the hostname from a target URL or hostname
func GetHostFromTarget(target string) string {
	// Remove protocol if present
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil && u.Host != "" {
			// Remove port if present
			host, _, _ := net.SplitHostPort(u.Host)
			if host != "" {
				return host
			}
			return u.Host
		}
	}

	// Remove port if present
	host, _, _ := net.SplitHostPort(target)
	if host != "" {
		return host
	}

	return target
}

// ============================================================================
// WHOIS/RDAP Helpers
// ============================================================================

// WHOISResult contains WHOIS lookup results
type WHOISResult struct {
	Domain      string            `json:"domain"`
	Registrar   string            `json:"registrar,omitempty"`
	Created     string            `json:"created,omitempty"`
	Expires     string            `json:"expires,omitempty"`
	Updated     string            `json:"updated,omitempty"`
	Nameservers []string          `json:"nameservers,omitempty"`
	Contacts    map[string]string `json:"contacts,omitempty"`
	Raw         string            `json:"raw,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// RDAPResponse represents a simplified RDAP response
type RDAPResponse struct {
	Handle  string   `json:"handle"`
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Handle     string        `json:"handle"`
		Roles      []string      `json:"roles"`
		VCardArray []interface{} `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

// FetchRDAP fetches RDAP information for a domain
func FetchRDAP(ctx context.Context, domain string) (*WHOISResult, error) {
	result := &WHOISResult{Domain: domain}

	// Use rdap.org bootstrap
	rdapURL := fmt.Sprintf("https://rdap.org/domain/%s", domain)

	client := NewHTTPClient(30 * time.Second)
	resp, err := client.Get(ctx, rdapURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result, nil
	}

	body := resp.Body

	result.Raw = string(body)

	// Parse RDAP response
	var rdap RDAPResponse
	if err := json.Unmarshal(body, &rdap); err == nil {
		result.Domain = rdap.LDHName

		// Extract dates
		for _, event := range rdap.Events {
			switch event.EventAction {
			case "registration":
				result.Created = event.EventDate
			case "expiration":
				result.Expires = event.EventDate
			case "last update":
				result.Updated = event.EventDate
			}
		}

		// Extract nameservers
		for _, ns := range rdap.Nameservers {
			result.Nameservers = append(result.Nameservers, ns.LDHName)
		}

		// Extract registrar from entities
		for _, entity := range rdap.Entities {
			for _, role := range entity.Roles {
				if role == "registrar" {
					// Try to extract name from vCard
					if len(entity.VCardArray) > 1 {
						if vcard, ok := entity.VCardArray[1].([]interface{}); ok {
							for _, item := range vcard {
								if arr, ok := item.([]interface{}); ok && len(arr) > 0 {
									if key, ok := arr[0].(string); ok && key == "fn" && len(arr) > 3 {
										if name, ok := arr[3].(string); ok {
											result.Registrar = name
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return result, nil
}

// ============================================================================
// Certificate Transparency Helpers
// ============================================================================

// CRTSHResponse represents a response from crt.sh
type CRTSHResponse struct {
	ID         int64  `json:"id"`
	LoggedAt   string `json:"entry_timestamp"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	CommonName string `json:"common_name"`
	NameValues string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
}

// FetchCRTSH queries crt.sh for certificate transparency logs
func FetchCRTSH(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := NewHTTPClient(60 * time.Second)
	resp, err := client.Get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from crt.sh", resp.StatusCode)
	}

	body := resp.Body

	var records []CRTSHResponse
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, err
	}

	// Extract unique subdomains
	subdomainMap := make(map[string]bool)
	for _, record := range records {
		// Parse name_values (can contain multiple domains)
		names := strings.Split(record.NameValues, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" && !strings.HasPrefix(name, "*.") {
				// Remove wildcard prefix if present
				name = strings.TrimPrefix(name, "*.")
				if strings.HasSuffix(name, domain) && name != domain {
					subdomainMap[name] = true
				}
			}
		}
	}

	// Convert map to slice
	subdomains := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

// ============================================================================
// IP Info Helpers
// ============================================================================

// IPInfoResponse represents a response from ipinfo.io
type IPInfoResponse struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
	ASN      struct {
		ASN    string `json:"asn"`
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Route  string `json:"route"`
		Type   string `json:"type"`
	} `json:"asn,omitempty"`
	Company struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Type   string `json:"type"`
	} `json:"company,omitempty"`
}

// FetchIPInfo fetches IP information from ipinfo.io
func FetchIPInfo(ctx context.Context, ip string) (*IPInfoResponse, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	client := NewHTTPClient(30 * time.Second)
	resp, err := client.Get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from ipinfo.io", resp.StatusCode)
	}

	body := resp.Body

	var info IPInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// NormalizeDomain normalizes a domain name
func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// IsSubdomain checks if a domain is a subdomain of another
func IsSubdomain(subdomain, domain string) bool {
	subdomain = NormalizeDomain(subdomain)
	domain = NormalizeDomain(domain)

	if subdomain == domain {
		return false
	}

	return strings.HasSuffix(subdomain, "."+domain)
}

// ExtractDomain extracts the main domain from a hostname
func ExtractDomain(hostname string) string {
	hostname = NormalizeDomain(hostname)

	// List of public suffixes (simplified - use proper Public Suffix List for production)
	publicSuffixes := []string{
		".com", ".org", ".net", ".edu", ".gov", ".mil", ".int",
		".co.uk", ".org.uk", ".net.uk", ".ac.uk", ".gov.uk",
		".co.jp", ".or.jp", ".ne.jp", ".go.jp", ".ac.jp",
		".co.de", ".com.au", ".net.au", ".org.au", ".gov.au",
		".co.nz", ".org.nz", ".net.nz", ".ac.nz", ".govt.nz",
		".co.in", ".org.in", ".net.in", ".ac.in", ".gov.in",
		".co", ".io", ".app", ".dev", ".cloud", ".tech", ".online",
	}

	for _, suffix := range publicSuffixes {
		if idx := strings.LastIndex(hostname, suffix); idx != -1 {
			// Find the next dot before this suffix
			prefix := hostname[:idx]
			if lastDot := strings.LastIndex(prefix, "."); lastDot != -1 {
				return prefix[lastDot+1:] + suffix
			}
			return hostname
		}
	}

	// Fallback: return last two parts
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}

	return hostname
}

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	ticker *time.Ticker
	done   chan bool
}

// NewRateLimiter creates a rate limiter with specified requests per second
func NewRateLimiter(rps int) *RateLimiter {
	interval := time.Second / time.Duration(rps)
	return &RateLimiter{
		ticker: time.NewTicker(interval),
		done:   make(chan bool),
	}
}

// Wait blocks until the next request is allowed
func (r *RateLimiter) Wait() {
	<-r.ticker.C
}

// Stop stops the rate limiter
func (r *RateLimiter) Stop() {
	r.ticker.Stop()
	close(r.done)
}

// ConcurrentPool manages a pool of concurrent workers
type ConcurrentPool struct {
	maxWorkers int
	semaphore  chan struct{}
}

// NewConcurrentPool creates a new concurrent pool
func NewConcurrentPool(maxWorkers int) *ConcurrentPool {
	return &ConcurrentPool{
		maxWorkers: maxWorkers,
		semaphore:  make(chan struct{}, maxWorkers),
	}
}

// Acquire acquires a slot in the pool
func (p *ConcurrentPool) Acquire() {
	p.semaphore <- struct{}{}
}

// Release releases a slot in the pool
func (p *ConcurrentPool) Release() {
	<-p.semaphore
}

// IsAvailable checks if the pool has available slots
func (p *ConcurrentPool) IsAvailable() bool {
	select {
	case p.semaphore <- struct{}{}:
		<-p.semaphore
		return true
	default:
		return false
	}
}

var (
	httpURLPattern = regexp.MustCompile(`https?://[^\s<>"{}|\\^\[\]]+`)
	ipPattern      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	emailPattern   = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	domainPattern  = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
)

// ExtractURLs extracts URLs from text
func ExtractURLs(text string) []string {
	return httpURLPattern.FindAllString(text, -1)
}

// ExtractIPs extracts IP addresses from text
func ExtractIPs(text string) []string {
	matches := ipPattern.FindAllString(text, -1)
	var validIPs []string
	for _, ip := range matches {
		if IsValidIP(ip) {
			validIPs = append(validIPs, ip)
		}
	}
	return validIPs
}

// ExtractEmails extracts email addresses from text
func ExtractEmails(text string) []string {
	return emailPattern.FindAllString(text, -1)
}

// ExtractDomains extracts domain names from text
func ExtractDomains(text string) []string {
	domains := domainPattern.FindAllString(text, -1)
	seen := make(map[string]bool)
	var unique []string
	for _, domain := range domains {
		domain = strings.ToLower(domain)
		if !seen[domain] {
			seen[domain] = true
			unique = append(unique, domain)
		}
	}
	return unique
}

// ============================================================================
// HTTP Header Analysis
// ============================================================================

// SecurityHeaders contains common security headers
type SecurityHeaders struct {
	ContentSecurityPolicy   string `json:"content_security_policy,omitempty"`
	StrictTransportSecurity string `json:"strict_transport_security,omitempty"`
	XFrameOptions           string `json:"x_frame_options,omitempty"`
	XContentTypeOptions     string `json:"x_content_type_options,omitempty"`
	ReferrerPolicy          string `json:"referrer_policy,omitempty"`
	PermissionsPolicy       string `json:"permissions_policy,omitempty"`
	XSSProtection           string `json:"x_xss_protection,omitempty"`
}

// ParseSecurityHeaders extracts security headers from HTTP response
func ParseSecurityHeaders(headers http.Header) *SecurityHeaders {
	return &SecurityHeaders{
		ContentSecurityPolicy:   headers.Get("Content-Security-Policy"),
		StrictTransportSecurity: headers.Get("Strict-Transport-Security"),
		XFrameOptions:           headers.Get("X-Frame-Options"),
		XContentTypeOptions:     headers.Get("X-Content-Type-Options"),
		ReferrerPolicy:          headers.Get("Referrer-Policy"),
		PermissionsPolicy:       headers.Get("Permissions-Policy"),
		XSSProtection:           headers.Get("X-XSS-Protection"),
	}
}

// SecurityHeaderScore calculates a security score based on headers
func SecurityHeaderScore(headers *SecurityHeaders) (score int, missing []string) {
	score = 0
	missing = []string{}

	if headers.ContentSecurityPolicy != "" {
		score += 20
	} else {
		missing = append(missing, "Content-Security-Policy")
	}

	if headers.StrictTransportSecurity != "" {
		score += 20
	} else {
		missing = append(missing, "Strict-Transport-Security")
	}

	if headers.XFrameOptions != "" {
		score += 15
	} else {
		missing = append(missing, "X-Frame-Options")
	}

	if headers.XContentTypeOptions != "" {
		score += 15
	} else {
		missing = append(missing, "X-Content-Type-Options")
	}

	if headers.ReferrerPolicy != "" {
		score += 15
	} else {
		missing = append(missing, "Referrer-Policy")
	}

	if headers.PermissionsPolicy != "" {
		score += 15
	} else {
		missing = append(missing, "Permissions-Policy")
	}

	return score, missing
}

// ============================================================================
// Banner Parsing
// ============================================================================

// ParseSSHBanner parses SSH version from banner
func ParseSSHBanner(banner string) (version string, software string) {
	// SSH banner format: SSH-protoversion-softwareversion SP comments CR LF
	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, " ", 2)
		versionParts := strings.SplitN(parts[0], "-", 3)
		if len(versionParts) >= 2 {
			version = versionParts[1]
		}
		if len(versionParts) >= 3 {
			software = versionParts[2]
		}
	}
	return
}

// ParseHTTPBanner parses HTTP server from banner
func ParseHTTPBanner(banner string) (server string, statusCode int) {
	// HTTP/1.1 200 OK format
	if strings.HasPrefix(banner, "HTTP/") {
		parts := strings.SplitN(banner, " ", 3)
		if len(parts) >= 2 {
			code, _ := strconv.Atoi(parts[1])
			statusCode = code
		}
	}
	return
}

// ParseFTPBanner parses FTP server from banner
func ParseFTPBanner(banner string) (server string, ready bool) {
	// FTP banner usually starts with 220
	if strings.HasPrefix(banner, "220 ") {
		ready = true
		server = strings.TrimPrefix(banner, "220 ")
		server = strings.TrimSpace(server)
	}
	return
}

// ParseSMTPBanner parses SMTP server from banner
func ParseSMTPBanner(banner string) (server string, ready bool) {
	// SMTP banner usually starts with 220
	if strings.HasPrefix(banner, "220 ") {
		ready = true
		// Extract server name before space or ESMTP
		parts := strings.SplitN(banner, " ", 3)
		if len(parts) >= 2 {
			server = parts[1]
		}
	}
	return
}

// IsWebSocketRequest checks if a request is a WebSocket upgrade request
func IsWebSocketRequest(headers http.Header) bool {
	return strings.ToLower(headers.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(headers.Get("Connection")), "upgrade")
}

// ReadBody reads the response body with a size limit
func ReadBody(resp *http.Response, maxSize int64) ([]byte, error) {
	if maxSize == 0 {
		maxSize = 10 * 1024 * 1024 // 10MB default
	}

	reader := io.LimitReader(resp.Body, maxSize)
	return io.ReadAll(reader)
}

// ReadBodyString reads the response body as string with a size limit
func ReadBodyString(resp *http.Response, maxSize int64) (string, error) {
	body, err := ReadBody(resp, maxSize)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ParseJSONResponse parses JSON response
func ParseJSONResponse(resp *http.Response, v interface{}) error {
	body, err := ReadBody(resp, 10*1024*1024)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// ============================================================================
// Buffer Pool
// ============================================================================

var bytesBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// GetBuffer gets a buffer from the pool
func GetBuffer() *bytes.Buffer {
	return bytesBufferPool.Get().(*bytes.Buffer)
}

// PutBuffer returns a buffer to the pool
func PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bytesBufferPool.Put(buf)
}

// ReaderPool provides a pool of reusable bufio.Readers
type ReaderPool struct {
	pool sync.Pool
}

// NewReaderPool creates a new reader pool
func NewReaderPool() *ReaderPool {
	return &ReaderPool{
		pool: sync.Pool{
			New: func() interface{} {
				return bufio.NewReader(nil)
			},
		},
	}
}

// Get gets a reader from the pool
func (p *ReaderPool) Get(r io.Reader) *bufio.Reader {
	reader := p.pool.Get().(*bufio.Reader)
	reader.Reset(r)
	return reader
}

// Put returns a reader to the pool
func (p *ReaderPool) Put(r *bufio.Reader) {
	r.Reset(nil)
	p.pool.Put(r)
}
