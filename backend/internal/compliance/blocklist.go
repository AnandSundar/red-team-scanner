package compliance

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// BlockReason represents the reason a target was blocked
type BlockReason string

const (
	BlockReasonRFC1918   BlockReason = "rfc1918_private_range"
	BlockReasonLoopback  BlockReason = "loopback_address"
	BlockReasonLinkLocal BlockReason = "link_local_address"
	BlockReasonReserved  BlockReason = "reserved_range"
	BlockReasonDomain    BlockReason = "blocked_domain"
	BlockReasonPattern   BlockReason = "blocked_pattern"
	BlockReasonCIDR      BlockReason = "blocked_cidr"
)

// BlockResult contains the result of a blocklist check
type BlockResult struct {
	Allowed bool        `json:"allowed"`
	Reason  BlockReason `json:"reason,omitempty"`
	Message string      `json:"message,omitempty"`
}

// Error messages for blocked targets
const (
	ErrorBlockedRFC1918   = "Scan blocked: Target is in a restricted IP range (RFC1918 private address). This scan has been logged for compliance."
	ErrorBlockedLoopback  = "Scan blocked: Target is a loopback address. This scan has been logged for compliance."
	ErrorBlockedLinkLocal = "Scan blocked: Target is a link-local address. This scan has been logged for compliance."
	ErrorBlockedReserved  = "Scan blocked: Target is in a reserved IP range. This scan has been logged for compliance."
	ErrorBlockedDomain    = "Scan blocked: Target domain is restricted. This scan has been logged for compliance."
	ErrorBlockedPattern   = "Scan blocked: Target matches a restricted pattern. This scan has been logged for compliance."
	ErrorBlockedCIDR      = "Scan blocked: Target is in a blocked CIDR range. This scan has been logged for compliance."
)

// Blocklist manages targets that should not be scanned
type Blocklist struct {
	domains        []string
	patterns       []*regexp.Regexp
	cidrs          []*net.IPNet
	selfHostedMode bool
}

// NewBlocklist creates a new blocklist with RFC1918 and other blocked targets
func NewBlocklist() *Blocklist {
	// Check if self-hosted mode is enabled
	selfHosted := os.Getenv("SELF_HOSTED_MODE") == "true" || os.Getenv("SELF_HOSTED_MODE") == "1"

	b := &Blocklist{
		domains: []string{
			".gov",
			".mil",
			"police",
			"hospital",
			"emergency",
			"localhost",
		},
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\.(gov|mil)$`),
			regexp.MustCompile(`(?i)(hospital|clinic|healthcare|medical)`),
			regexp.MustCompile(`(?i)(police|fire|emergency|911)`),
			regexp.MustCompile(`(?i)(school|university|\.edu)`),
			regexp.MustCompile(`(?i)(cia|fbi|nsa|dod|defense)`),
			regexp.MustCompile(`(?i)(bank|finance|payment)`),
		},
		selfHostedMode: selfHosted,
	}

	// Add RFC1918 private networks
	privateCIDRs := []string{
		"10.0.0.0/8",     // RFC1918 Private
		"172.16.0.0/12",  // RFC1918 Private
		"192.168.0.0/16", // RFC1918 Private
	}

	// Add loopback addresses
	loopbackCIDRs := []string{
		"127.0.0.0/8", // IPv4 Loopback
		"::1/128",     // IPv6 Loopback
	}

	// Add link-local addresses
	linkLocalCIDRs := []string{
		"169.254.0.0/16", // IPv4 Link-local (includes AWS metadata)
		"fe80::/10",      // IPv6 Link-local
	}

	// Add reserved ranges
	reservedCIDRs := []string{
		"0.0.0.0/8",   // Current network
		"240.0.0.0/4", // Reserved for future use
		"fc00::/7",    // IPv6 Unique local
	}

	// Combine all CIDRs
	allCIDRs := append(privateCIDRs, loopbackCIDRs...)
	allCIDRs = append(allCIDRs, linkLocalCIDRs...)
	allCIDRs = append(allCIDRs, reservedCIDRs...)

	for _, cidr := range allCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			b.cidrs = append(b.cidrs, ipnet)
		}
	}

	return b
}

// IsAllowed checks if a target is allowed to be scanned
// Returns BlockResult with detailed information
func (b *Blocklist) IsAllowed(target string) BlockResult {
	// In self-hosted mode, allow all targets
	if b.selfHostedMode {
		return BlockResult{Allowed: true}
	}

	// Extract host from URL if needed
	host := b.extractHost(target)

	// Check if it's an IP address
	ip := net.ParseIP(host)
	if ip != nil {
		return b.checkIP(ip)
	}

	// Check blocked domains
	hostLower := strings.ToLower(host)
	for _, domain := range b.domains {
		if strings.Contains(hostLower, domain) {
			return BlockResult{
				Allowed: false,
				Reason:  BlockReasonDomain,
				Message: ErrorBlockedDomain,
			}
		}
	}

	// Check blocked patterns
	for _, pattern := range b.patterns {
		if pattern.MatchString(hostLower) {
			return BlockResult{
				Allowed: false,
				Reason:  BlockReasonPattern,
				Message: ErrorBlockedPattern,
			}
		}
	}

	return BlockResult{Allowed: true}
}

// IsAllowedBool returns true if the target is allowed (simple boolean check)
func (b *Blocklist) IsAllowedBool(target string) bool {
	result := b.IsAllowed(target)
	return result.Allowed
}

// CheckWithReason checks if a target is allowed and returns detailed reason if blocked
func (b *Blocklist) CheckWithReason(target string) (bool, BlockReason, string) {
	result := b.IsAllowed(target)
	return result.Allowed, result.Reason, result.Message
}

// checkIP checks if an IP address is blocked
func (b *Blocklist) checkIP(ip net.IP) BlockResult {
	// Check RFC1918 ranges first
	rfc1918CIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range rfc1918CIDRs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil && ipnet.Contains(ip) {
			return BlockResult{
				Allowed: false,
				Reason:  BlockReasonRFC1918,
				Message: ErrorBlockedRFC1918,
			}
		}
	}

	// Check loopback
	if ip.IsLoopback() {
		return BlockResult{
			Allowed: false,
			Reason:  BlockReasonLoopback,
			Message: ErrorBlockedLoopback,
		}
	}

	// Check link-local (169.254.0.0/16)
	linkLocalCIDRs := []string{
		"169.254.0.0/16",
		"fe80::/10",
	}

	for _, cidr := range linkLocalCIDRs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil && ipnet.Contains(ip) {
			return BlockResult{
				Allowed: false,
				Reason:  BlockReasonLinkLocal,
				Message: ErrorBlockedLinkLocal,
			}
		}
	}

	// Check reserved ranges
	reservedCIDRs := []string{
		"0.0.0.0/8",
		"240.0.0.0/4",
	}

	for _, cidr := range reservedCIDRs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil && ipnet.Contains(ip) {
			return BlockResult{
				Allowed: false,
				Reason:  BlockReasonReserved,
				Message: ErrorBlockedReserved,
			}
		}
	}

	// Check custom CIDR blocks
	for _, cidr := range b.cidrs {
		if cidr.Contains(ip) {
			return BlockResult{
				Allowed: false,
				Reason:  BlockReasonCIDR,
				Message: ErrorBlockedCIDR,
			}
		}
	}

	return BlockResult{Allowed: true}
}

// extractHost extracts the host from a URL or returns the input if it's already a host
func (b *Blocklist) extractHost(target string) string {
	host := target
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			host = u.Host
			// Remove port if present
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
	}
	return host
}

// IsRFC1918 checks if target is in RFC1918 private address space
func (b *Blocklist) IsRFC1918(target string) bool {
	if b.selfHostedMode {
		return false
	}

	host := b.extractHost(target)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	rfc1918CIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range rfc1918CIDRs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil && ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// IsLoopback checks if target is a loopback address
func (b *Blocklist) IsLoopback(target string) bool {
	if b.selfHostedMode {
		return false
	}

	host := b.extractHost(target)
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}

	return ip.IsLoopback()
}

// IsLinkLocal checks if target is a link-local address (including AWS metadata)
func (b *Blocklist) IsLinkLocal(target string) bool {
	if b.selfHostedMode {
		return false
	}

	host := b.extractHost(target)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	linkLocalCIDRs := []string{
		"169.254.0.0/16",
		"fe80::/10",
	}

	for _, cidr := range linkLocalCIDRs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil && ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// IsReserved checks if target is in a reserved IP range
func (b *Blocklist) IsReserved(target string) bool {
	if b.selfHostedMode {
		return false
	}

	host := b.extractHost(target)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	reservedCIDRs := []string{
		"0.0.0.0/8",
		"240.0.0.0/4",
	}

	for _, cidr := range reservedCIDRs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil && ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// AddDomain adds a domain to the blocklist
func (b *Blocklist) AddDomain(domain string) {
	b.domains = append(b.domains, strings.ToLower(domain))
}

// AddPattern adds a regex pattern to the blocklist
func (b *Blocklist) AddPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	b.patterns = append(b.patterns, re)
	return nil
}

// AddCIDR adds a CIDR range to the blocklist
func (b *Blocklist) AddCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	b.cidrs = append(b.cidrs, ipnet)
	return nil
}

// SetSelfHostedMode enables or disables self-hosted mode
func (b *Blocklist) SetSelfHostedMode(enabled bool) {
	b.selfHostedMode = enabled
}

// IsSelfHostedMode returns true if self-hosted mode is enabled
func (b *Blocklist) IsSelfHostedMode() bool {
	return b.selfHostedMode
}

// GetBlockedRanges returns a list of all blocked IP ranges
func (b *Blocklist) GetBlockedRanges() []string {
	ranges := []string{
		"10.0.0.0/8 (RFC1918 Private)",
		"172.16.0.0/12 (RFC1918 Private)",
		"192.168.0.0/16 (RFC1918 Private)",
		"127.0.0.0/8 (IPv4 Loopback)",
		"::1/128 (IPv6 Loopback)",
		"169.254.0.0/16 (Link-local / AWS Metadata)",
		"fe80::/10 (IPv6 Link-local)",
		"0.0.0.0/8 (Reserved)",
		"240.0.0.0/4 (Reserved)",
		"fc00::/7 (IPv6 Unique Local)",
	}
	return ranges
}

// Whitelist manages explicitly allowed targets
type Whitelist struct {
	targets []string
	cidrs   []*net.IPNet
}

// NewWhitelist creates a new whitelist
func NewWhitelist() *Whitelist {
	return &Whitelist{
		targets: []string{},
		cidrs:   []*net.IPNet{},
	}
}

// AddTarget adds a target to the whitelist
func (w *Whitelist) AddTarget(target string) {
	w.targets = append(w.targets, strings.ToLower(target))
}

// AddCIDR adds a CIDR range to the whitelist
func (w *Whitelist) AddCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	w.cidrs = append(w.cidrs, ipnet)
	return nil
}

// IsWhitelisted checks if a target is explicitly whitelisted
func (w *Whitelist) IsWhitelisted(target string) bool {
	host := strings.ToLower(target)

	// Check exact matches
	for _, t := range w.targets {
		if host == t || strings.HasSuffix(host, t) {
			return true
		}
	}

	// Check CIDR ranges
	ip := net.ParseIP(target)
	if ip != nil {
		for _, cidr := range w.cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// BlocklistError represents a blocklist violation error
type BlocklistError struct {
	Target string
	Reason BlockReason
}

func (e *BlocklistError) Error() string {
	return fmt.Sprintf("Target '%s' blocked: %s", e.Target, e.Reason)
}

// NewBlocklistError creates a new blocklist error
func NewBlocklistError(target string, reason BlockReason) *BlocklistError {
	return &BlocklistError{
		Target: target,
		Reason: reason,
	}
}
