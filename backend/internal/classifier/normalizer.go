package classifier

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// TargetNormalizer handles parsing and normalization of target inputs
type TargetNormalizer struct {
	defaultTimeout int
}

// NewTargetNormalizer creates a new target normalizer
func NewTargetNormalizer() *TargetNormalizer {
	return &TargetNormalizer{
		defaultTimeout: 30,
	}
}

// NormalizedTarget represents a parsed and normalized target
type NormalizedTarget struct {
	Raw         string
	URL         *url.URL
	Host        string
	IP          net.IP
	Port        int
	IsIP        bool
	Protocol    string // http, https, ws, wss, grpc
	Path        string
	IsCDN       bool
	CDNProvider string
}

// Normalize parses and normalizes a raw target string
func (n *TargetNormalizer) Normalize(rawTarget string) (*NormalizedTarget, error) {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return nil, fmt.Errorf("empty target")
	}

	// Strip trailing slashes
	rawTarget = strings.TrimRight(rawTarget, "/")

	// Detect and handle protocol
	protocol, targetWithoutProtocol := n.extractProtocol(rawTarget)

	// Check if it's a bare IP address
	if ip := net.ParseIP(targetWithoutProtocol); ip != nil {
		return n.createBareIPTarget(rawTarget, ip, protocol), nil
	}

	// Check if it's IP:port format
	if ip, port, err := n.parseIPWithPort(targetWithoutProtocol); err == nil {
		return n.createBareIPTarget(rawTarget, ip, protocol, port), nil
	}

	// Parse as URL
	urlStr := n.ensureProtocol(rawTarget, protocol)
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return n.createURLTarget(rawTarget, parsedURL, protocol), nil
}

// extractProtocol detects the protocol from a target string
func (n *TargetNormalizer) extractProtocol(target string) (string, string) {
	protocols := []struct {
		prefix   string
		protocol string
	}{
		{"https://", "https"},
		{"http://", "http"},
		{"wss://", "wss"},
		{"ws://", "ws"},
		{"grpc://", "grpc"},
		{"grpcs://", "grpcs"},
	}

	lowerTarget := strings.ToLower(target)
	for _, p := range protocols {
		if strings.HasPrefix(lowerTarget, p.prefix) {
			return p.protocol, target[len(p.prefix):]
		}
	}

	return "", target
}

// ensureProtocol ensures the URL has a protocol
func (n *TargetNormalizer) ensureProtocol(target, detectedProtocol string) string {
	if detectedProtocol != "" {
		// Reconstruct with normalized protocol
		_, withoutProto := n.extractProtocol(target)
		switch detectedProtocol {
		case "https":
			return "https://" + withoutProto
		case "http":
			return "http://" + withoutProto
		case "wss":
			return "wss://" + withoutProto
		case "ws":
			return "ws://" + withoutProto
		case "grpc":
			return "grpc://" + withoutProto
		case "grpcs":
			return "grpcs://" + withoutProto
		}
	}

	// Default to https
	return "https://" + target
}

// parseIPWithPort parses an IP:port combination
func (n *TargetNormalizer) parseIPWithPort(target string) (net.IP, int, error) {
	// IPv6 format [ip]:port
	if strings.HasPrefix(target, "[") {
		idx := strings.LastIndex(target, "]")
		if idx == -1 {
			return nil, 0, fmt.Errorf("invalid IPv6 format")
		}
		ipStr := target[1:idx]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid IPv6 address")
		}

		port := 0
		if len(target) > idx+2 && target[idx+1] == ':' {
			var err error
			port, err = strconv.Atoi(target[idx+2:])
			if err != nil {
				return nil, 0, fmt.Errorf("invalid port")
			}
		}
		return ip, port, nil
	}

	// IPv4:port format
	parts := strings.Split(target, ":")
	if len(parts) == 2 {
		ip := net.ParseIP(parts[0])
		if ip == nil {
			return nil, 0, fmt.Errorf("not an IP address")
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port")
		}
		return ip, port, nil
	}

	return nil, 0, fmt.Errorf("not IP:port format")
}

// createBareIPTarget creates a target for a bare IP address
func (n *TargetNormalizer) createBareIPTarget(raw string, ip net.IP, protocol string, port ...int) *NormalizedTarget {
	p := 0
	if len(port) > 0 {
		p = port[0]
	}

	// Determine default port based on protocol
	if p == 0 {
		switch protocol {
		case "https", "grpcs":
			p = 443
		case "http", "grpc":
			p = 80
		case "wss":
			p = 443
		case "ws":
			p = 80
		default:
			p = 443 // Default to 443 for bare IPs
		}
	}

	protocol = n.normalizeProtocol(protocol, p)

	// Construct URL from IP
	var urlStr string
	if ip.To4() != nil {
		urlStr = fmt.Sprintf("%s://%s:%d", protocol, ip.String(), p)
	} else {
		urlStr = fmt.Sprintf("%s://[%s]:%d", protocol, ip.String(), p)
	}

	parsedURL, _ := url.Parse(urlStr)

	return &NormalizedTarget{
		Raw:      raw,
		URL:      parsedURL,
		Host:     ip.String(),
		IP:       ip,
		Port:     p,
		IsIP:     true,
		Protocol: protocol,
		Path:     "/",
		IsCDN:    false,
	}
}

// createURLTarget creates a target from a parsed URL
func (n *TargetNormalizer) createURLTarget(raw string, parsedURL *url.URL, protocol string) *NormalizedTarget {
	host := parsedURL.Hostname()
	port, _ := strconv.Atoi(parsedURL.Port())

	// Determine default port if not specified
	if port == 0 {
		port = n.getDefaultPort(protocol)
	}

	// Normalize protocol based on port
	protocol = n.normalizeProtocol(protocol, port)

	// Try to resolve IP
	ip := net.ParseIP(host)
	isIP := ip != nil
	if !isIP {
		// Will be resolved during probing
		ip = nil
	}

	// Detect CDN
	isCDN, cdnProvider := n.detectCDN(host)

	return &NormalizedTarget{
		Raw:         raw,
		URL:         parsedURL,
		Host:        host,
		IP:          ip,
		Port:        port,
		IsIP:        isIP,
		Protocol:    protocol,
		Path:        parsedURL.Path,
		IsCDN:       isCDN,
		CDNProvider: cdnProvider,
	}
}

// getDefaultPort returns the default port for a protocol
func (n *TargetNormalizer) getDefaultPort(protocol string) int {
	switch protocol {
	case "https", "grpcs":
		return 443
	case "http", "grpc":
		return 80
	case "wss":
		return 443
	case "ws":
		return 80
	default:
		return 443
	}
}

// normalizeProtocol normalizes protocol based on port
func (n *TargetNormalizer) normalizeProtocol(protocol string, port int) string {
	if protocol != "" {
		return protocol
	}
	if port == 443 {
		return "https"
	}
	if port == 80 {
		return "http"
	}
	return "https" // Default
}

// detectCDN detects if a host is behind a CDN
func (n *TargetNormalizer) detectCDN(host string) (bool, string) {
	cdnPatterns := map[string]*regexp.Regexp{
		"Cloudflare": regexp.MustCompile(`(?i)(cloudflare|cf-)`),
		"Akamai":     regexp.MustCompile(`(?i)(akamai|akamaized)`),
		"Fastly":     regexp.MustCompile(`(?i)(fastly|fastlylb)`),
		"CloudFront": regexp.MustCompile(`(?i)(cloudfront|aws)`),
		"Incapsula":  regexp.MustCompile(`(?i)(incapsula|imperva)`),
		"Sucuri":     regexp.MustCompile(`(?i)(sucuri)`),
		"MaxCDN":     regexp.MustCompile(`(?i)(maxcdn)`),
		"KeyCDN":     regexp.MustCompile(`(?i)(keycdn)`),
		"BunnyCDN":   regexp.MustCompile(`(?i)(bunnycdn|b-cdn)`),
		"StackPath":  regexp.MustCompile(`(?i)(stackpath)`),
	}

	for provider, pattern := range cdnPatterns {
		if pattern.MatchString(host) {
			return true, provider
		}
	}

	return false, ""
}

// ValidateIPv4 validates an IPv4 address
func (n *TargetNormalizer) ValidateIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return parsedIP.To4() != nil
}

// ValidateIPv6 validates an IPv6 address
func (n *TargetNormalizer) ValidateIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return parsedIP.To4() == nil && parsedIP.To16() != nil
}

// ExtractDomain extracts the domain from a URL or host string
func (n *TargetNormalizer) ExtractDomain(target string) string {
	// Remove protocol if present
	_, withoutProto := n.extractProtocol(target)

	// Remove port if present
	if idx := strings.Index(withoutProto, ":"); idx != -1 {
		withoutProto = withoutProto[:idx]
	}

	// Remove path if present
	if idx := strings.Index(withoutProto, "/"); idx != -1 {
		withoutProto = withoutProto[:idx]
	}

	return strings.ToLower(withoutProto)
}

// NormalizePath normalizes a URL path
func (n *TargetNormalizer) NormalizePath(path string) string {
	if path == "" {
		return "/"
	}

	// Ensure leading slash
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Remove trailing slash (except for root)
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}

	return path
}

// BuildURL constructs a URL from components
func (n *TargetNormalizer) BuildURL(protocol, host string, port int, path string) string {
	// Determine if we need to include port
	includePort := true
	switch protocol {
	case "https", "grpcs", "wss":
		if port == 443 {
			includePort = false
		}
	case "http", "grpc", "ws":
		if port == 80 {
			includePort = false
		}
	}

	var urlStr string
	if includePort {
		urlStr = fmt.Sprintf("%s://%s:%d%s", protocol, host, port, path)
	} else {
		urlStr = fmt.Sprintf("%s://%s%s", protocol, host, path)
	}

	return urlStr
}
