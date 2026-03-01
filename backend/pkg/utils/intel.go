// Package utils provides threat intelligence API clients
package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Cache Implementation for Intel Results
// ============================================================================

// IntelCache provides thread-safe caching for threat intelligence data
type IntelCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
	ttl   time.Duration
}

type cacheItem struct {
	data      interface{}
	timestamp time.Time
}

// NewIntelCache creates a new intel cache with specified TTL
func NewIntelCache(defaultTTL time.Duration) *IntelCache {
	cache := &IntelCache{
		items: make(map[string]cacheItem),
		ttl:   defaultTTL,
	}
	// Start cleanup goroutine
	go cache.cleanup()
	return cache
}

// Get retrieves an item from cache
func (c *IntelCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}

	if time.Since(item.timestamp) > c.ttl {
		return nil, false
	}

	return item.data, true
}

// Set stores an item in cache
func (c *IntelCache) Set(key string, data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = cacheItem{
		data:      data,
		timestamp: time.Now(),
	}
}

// cleanup removes expired items periodically
func (c *IntelCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		for key, item := range c.items {
			if time.Since(item.timestamp) > c.ttl {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

// ============================================================================
// Rate Limiter for Intel APIs
// ============================================================================

// IntelRateLimiter provides rate limiting for API calls
type IntelRateLimiter struct {
	mu          sync.Mutex
	requests    []time.Time
	maxRequests int
	window      time.Duration
}

// NewIntelRateLimiter creates a new rate limiter
func NewIntelRateLimiter(maxRequests int, window time.Duration) *IntelRateLimiter {
	return &IntelRateLimiter{
		requests:    make([]time.Time, 0),
		maxRequests: maxRequests,
		window:      window,
	}
}

// Wait blocks until a request is allowed
func (r *IntelRateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := time.Now()

		// Remove old requests outside the window
		validRequests := make([]time.Time, 0)
		for _, t := range r.requests {
			if now.Sub(t) < r.window {
				validRequests = append(validRequests, t)
			}
		}
		r.requests = validRequests

		// Check if we can make a request
		if len(r.requests) < r.maxRequests {
			r.requests = append(r.requests, now)
			r.mu.Unlock()
			return nil
		}

		r.mu.Unlock()

		// Wait and retry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			continue
		}
	}
}

// ============================================================================
// AbuseIPDB Client
// ============================================================================

// AbuseIPDBClient interacts with the AbuseIPDB API
type AbuseIPDBClient struct {
	apiKey     string
	httpClient *http.Client
	cache      *IntelCache
	baseURL    string
}

// AbuseIPDBResponse represents the API response
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		IsPublic             bool     `json:"isPublic"`
		IPVersion            int      `json:"ipVersion"`
		IsWhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		UsageType            string   `json:"usageType"`
		ISP                  string   `json:"isp"`
		Domain               string   `json:"domain"`
		Hostnames            []string `json:"hostnames"`
		IsTor                bool     `json:"isTor"`
		TotalReports         int      `json:"totalReports"`
		NumDistinctUsers     int      `json:"numDistinctUsers"`
		LastReportedAt       string   `json:"lastReportedAt"`
		Reports              []struct {
			ReportedAt          string `json:"reportedAt"`
			Comment             string `json:"comment"`
			Categories          []int  `json:"categories"`
			ReporterId          int    `json:"reporterId"`
			ReporterCountryCode string `json:"reporterCountryCode"`
			ReporterCountryName string `json:"reporterCountryName"`
		} `json:"reports"`
	} `json:"data"`
}

// AbuseIPDBResult contains processed AbuseIPDB data
type AbuseIPDBResult struct {
	IPAddress            string    `json:"ip_address"`
	AbuseConfidenceScore int       `json:"abuse_confidence_score"`
	UsageType            string    `json:"usage_type"`
	ISP                  string    `json:"isp"`
	Domain               string    `json:"domain"`
	IsWhitelisted        bool      `json:"is_whitelisted"`
	IsTor                bool      `json:"is_tor"`
	TotalReports         int       `json:"total_reports"`
	CountryCode          string    `json:"country_code"`
	Categories           []string  `json:"categories"`
	LastReportedAt       string    `json:"last_reported_at"`
	Timestamp            time.Time `json:"timestamp"`
}

// NewAbuseIPDBClient creates a new AbuseIPDB client
func NewAbuseIPDBClient() *AbuseIPDBClient {
	apiKey := os.Getenv("ABUSEIPDB_API_KEY")
	return &AbuseIPDBClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:   NewIntelCache(1 * time.Hour),
		baseURL: "https://api.abuseipdb.com/api/v2",
	}
}

// IsConfigured returns true if API key is set
func (c *AbuseIPDBClient) IsConfigured() bool {
	return c.apiKey != ""
}

// CheckIP queries AbuseIPDB for IP reputation
func (c *AbuseIPDBClient) CheckIP(ctx context.Context, ip string) (*AbuseIPDBResult, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("AbuseIPDB API key not configured")
	}

	// Check cache
	cacheKey := fmt.Sprintf("abuseipdb:%s", ip)
	if cached, ok := c.cache.Get(cacheKey); ok {
		return cached.(*AbuseIPDBResult), nil
	}

	// Build request
	reqURL := fmt.Sprintf("%s/check?ipAddress=%s&maxAgeInDays=90&verbose", c.baseURL, url.QueryEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process result
	result := &AbuseIPDBResult{
		IPAddress:            apiResp.Data.IPAddress,
		AbuseConfidenceScore: apiResp.Data.AbuseConfidenceScore,
		UsageType:            apiResp.Data.UsageType,
		ISP:                  apiResp.Data.ISP,
		Domain:               apiResp.Data.Domain,
		IsWhitelisted:        apiResp.Data.IsWhitelisted,
		IsTor:                apiResp.Data.IsTor,
		TotalReports:         apiResp.Data.TotalReports,
		CountryCode:          apiResp.Data.CountryCode,
		Timestamp:            time.Now(),
	}

	// Extract unique categories from reports
	categorySet := make(map[string]bool)
	for _, report := range apiResp.Data.Reports {
		for _, cat := range report.Categories {
			categorySet[getAbuseCategoryName(cat)] = true
		}
	}
	for cat := range categorySet {
		result.Categories = append(result.Categories, cat)
	}

	// Cache result
	c.cache.Set(cacheKey, result)

	return result, nil
}

func getAbuseCategoryName(id int) string {
	categories := map[int]string{
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
	if name, ok := categories[id]; ok {
		return name
	}
	return fmt.Sprintf("Category-%d", id)
}

// ============================================================================
// URLhaus Client
// ============================================================================

// URLhausClient interacts with the URLhaus API
type URLhausClient struct {
	httpClient *http.Client
	cache      *IntelCache
	baseURL    string
}

// URLhausResponse represents the API response
type URLhausResponse struct {
	QueryStatus string `json:"query_status"`
	ID          string `json:"id,omitempty"`
	URLStatus   string `json:"url_status,omitempty"`
	Host        string `json:"host,omitempty"`
	DateAdded   string `json:"date_added,omitempty"`
	Threat      string `json:"threat,omitempty"`
	Blacklists  struct {
		SpamhausDROP string `json:"spamhaus_drop"`
		Surbl        string `json:"surbl"`
		Gsb          string `json:"gsb"`
		PhishTank    string `json:"phishtank"`
	} `json:"blacklists,omitempty"`
	Tags     []string `json:"tags,omitempty` //
	Payloads []struct {
		FirstSeen      string `json:"firstseen"`
		Filename       string `json:"filename"`
		ContentType    string `json:"content_type"`
		ResponseSize   int    `json:"response_size"`
		ResponseSHA256 string `json:"response_sha256"`
	} `json:"payloads,omitempty"`
}

// URLhausResult contains processed URLhaus data
type URLhausResult struct {
	URL         string    `json:"url"`
	Host        string    `json:"host"`
	Status      string    `json:"status"`
	IsMalicious bool      `json:"is_malicious"`
	Threat      string    `json:"threat"`
	Tags        []string  `json:"tags"`
	Payloads    int       `json:"payloads"`
	Blacklisted bool      `json:"blacklisted"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewURLhausClient creates a new URLhaus client
func NewURLhausClient() *URLhausClient {
	return &URLhausClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:   NewIntelCache(24 * time.Hour),
		baseURL: "https://urlhaus-api.abuse.ch/v1",
	}
}

// CheckDomain queries URLhaus for domain reputation
func (c *URLhausClient) CheckDomain(ctx context.Context, domain string) (*URLhausResult, error) {
	// Check cache
	cacheKey := fmt.Sprintf("urlhaus:domain:%s", domain)
	if cached, ok := c.cache.Get(cacheKey); ok {
		return cached.(*URLhausResult), nil
	}

	// Build request
	data := url.Values{}
	data.Set("host", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/host/", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var apiResp URLhausResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process result
	result := &URLhausResult{
		Host:        domain,
		Status:      apiResp.QueryStatus,
		IsMalicious: apiResp.QueryStatus == "ok" && apiResp.URLStatus == "online",
		Threat:      apiResp.Threat,
		Tags:        apiResp.Tags,
		Payloads:    len(apiResp.Payloads),
		Timestamp:   time.Now(),
	}

	// Check blacklist status
	result.Blacklisted = apiResp.Blacklists.SpamhausDROP == "listed" ||
		apiResp.Blacklists.Surbl == "listed" ||
		apiResp.Blacklists.Gsb == "listed" ||
		apiResp.Blacklists.PhishTank == "listed"

	// Cache result
	c.cache.Set(cacheKey, result)

	return result, nil
}

// CheckURL queries URLhaus for specific URL
func (c *URLhausClient) CheckURL(ctx context.Context, targetURL string) (*URLhausResult, error) {
	// Check cache
	cacheKey := fmt.Sprintf("urlhaus:url:%s", sha256String(targetURL))
	if cached, ok := c.cache.Get(cacheKey); ok {
		return cached.(*URLhausResult), nil
	}

	// Build request
	data := url.Values{}
	data.Set("url", targetURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/url/", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var apiResp URLhausResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process result
	result := &URLhausResult{
		URL:         targetURL,
		Host:        apiResp.Host,
		Status:      apiResp.QueryStatus,
		IsMalicious: apiResp.QueryStatus == "ok" && apiResp.URLStatus == "online",
		Threat:      apiResp.Threat,
		Tags:        apiResp.Tags,
		Payloads:    len(apiResp.Payloads),
		Timestamp:   time.Now(),
	}

	result.Blacklisted = apiResp.Blacklists.SpamhausDROP == "listed" ||
		apiResp.Blacklists.Surbl == "listed" ||
		apiResp.Blacklists.Gsb == "listed" ||
		apiResp.Blacklists.PhishTank == "listed"

	// Cache result
	c.cache.Set(cacheKey, result)

	return result, nil
}

// ============================================================================
// NVD (National Vulnerability Database) Client
// ============================================================================

// NVDClient interacts with the NVD API
type NVDClient struct {
	httpClient  *http.Client
	cache       *IntelCache
	rateLimiter *IntelRateLimiter
	baseURL     string
}

// NVDResponse represents the API response
type NVDResponse struct {
	ResultsPerPage  int      `json:"resultsPerPage"`
	StartIndex      int      `json:"startIndex"`
	TotalResults    int      `json:"totalResults"`
	Vulnerabilities []NVDCVE `json:"vulnerabilities"`
}

// NVDCVE represents a single CVE entry
type NVDCVE struct {
	CVE struct {
		ID               string `json:"id"`
		SourceIdentifier string `json:"sourceIdentifier"`
		Published        string `json:"published"`
		LastModified     string `json:"lastModified"`
		VulnStatus       string `json:"vulnStatus"`
		Descriptions     []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CVSSV31 struct {
				Source   string `json:"source"`
				Type     string `json:"type"`
				CVSSData struct {
					Version               string  `json:"version"`
					VectorString          string  `json:"vectorString"`
					AttackVector          string  `json:"attackVector"`
					AttackComplexity      string  `json:"attackComplexity"`
					PrivilegesRequired    string  `json:"privilegesRequired"`
					UserInteraction       string  `json:"userInteraction"`
					Scope                 string  `json:"scope"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					BaseScore             float64 `json:"baseScore"`
					BaseSeverity          string  `json:"baseSeverity"`
				} `json:"cvssData"`
				ExploitabilityScore float64 `json:"exploitabilityScore"`
				ImpactScore         float64 `json:"impactScore"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
		References []struct {
			URL    string   `json:"url"`
			Source string   `json:"source"`
			Tags   []string `json:"tags"`
		} `json:"references"`
	} `json:"cve"`
}

// NVDResult contains processed CVE data
type NVDResult struct {
	ID               string    `json:"id"`
	Severity         string    `json:"severity"`
	CVSSScore        float64   `json:"cvss_score"`
	Description      string    `json:"description"`
	Published        string    `json:"published"`
	LastModified     string    `json:"last_modified"`
	References       []string  `json:"references"`
	AttackVector     string    `json:"attack_vector"`
	AttackComplexity string    `json:"attack_complexity"`
	UserInteraction  string    `json:"user_interaction"`
	Timestamp        time.Time `json:"timestamp"`
}

// NewNVDClient creates a new NVD client
func NewNVDClient() *NVDClient {
	return &NVDClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		cache:       NewIntelCache(24 * time.Hour),
		rateLimiter: NewIntelRateLimiter(5, 30*time.Second), // NVD limit: 5 requests per 30 seconds
		baseURL:     "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// SearchCVEs searches NVD for CVEs matching a keyword
func (c *NVDClient) SearchCVEs(ctx context.Context, keyword string, limit int) ([]NVDResult, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}

	// Check cache
	cacheKey := fmt.Sprintf("nvd:search:%s:%d", sha256String(keyword), limit)
	if cached, ok := c.cache.Get(cacheKey); ok {
		return cached.([]NVDResult), nil
	}

	// Rate limit
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// Build request
	reqURL := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=%d", c.baseURL, url.QueryEscape(keyword), limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process results
	results := make([]NVDResult, 0, len(apiResp.Vulnerabilities))
	for _, cve := range apiResp.Vulnerabilities {
		result := NVDResult{
			ID:           cve.CVE.ID,
			Published:    cve.CVE.Published,
			LastModified: cve.CVE.LastModified,
			Timestamp:    time.Now(),
			References:   []string{},
		}

		// Get English description
		for _, desc := range cve.CVE.Descriptions {
			if desc.Lang == "en" {
				result.Description = desc.Value
				break
			}
		}

		// Get CVSS v3.1 data if available
		if cve.CVE.Metrics.CVSSV31.CVSSData.BaseScore > 0 {
			cvss := cve.CVE.Metrics.CVSSV31.CVSSData
			result.CVSSScore = cvss.BaseScore
			result.Severity = cvss.BaseSeverity
			result.AttackVector = cvss.AttackVector
			result.AttackComplexity = cvss.AttackComplexity
			result.UserInteraction = cvss.UserInteraction
		}

		// Collect references
		for _, ref := range cve.CVE.References {
			if ref.URL != "" {
				result.References = append(result.References, ref.URL)
			}
		}

		results = append(results, result)
	}

	// Cache result
	c.cache.Set(cacheKey, results)

	return results, nil
}

// GetCVE retrieves a specific CVE by ID
func (c *NVDClient) GetCVE(ctx context.Context, cveID string) (*NVDResult, error) {
	// Check cache
	cacheKey := fmt.Sprintf("nvd:cve:%s", cveID)
	if cached, ok := c.cache.Get(cacheKey); ok {
		return cached.(*NVDResult), nil
	}

	// Rate limit
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// Build request
	reqURL := fmt.Sprintf("%s?cveId=%s", c.baseURL, url.QueryEscape(cveID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	// Process result
	cve := apiResp.Vulnerabilities[0]
	result := &NVDResult{
		ID:           cve.CVE.ID,
		Published:    cve.CVE.Published,
		LastModified: cve.CVE.LastModified,
		Timestamp:    time.Now(),
		References:   []string{},
	}

	// Get English description
	for _, desc := range cve.CVE.Descriptions {
		if desc.Lang == "en" {
			result.Description = desc.Value
			break
		}
	}

	// Get CVSS v3.1 data if available
	if cve.CVE.Metrics.CVSSV31.CVSSData.BaseScore > 0 {
		cvss := cve.CVE.Metrics.CVSSV31.CVSSData
		result.CVSSScore = cvss.BaseScore
		result.Severity = cvss.BaseSeverity
		result.AttackVector = cvss.AttackVector
		result.AttackComplexity = cvss.AttackComplexity
		result.UserInteraction = cvss.UserInteraction
	}

	// Collect references
	for _, ref := range cve.CVE.References {
		if ref.URL != "" {
			result.References = append(result.References, ref.URL)
		}
	}

	// Cache result
	c.cache.Set(cacheKey, result)

	return result, nil
}

// ============================================================================
// Shodan InternetDB Client
// ============================================================================

// ShodanClient interacts with Shodan InternetDB API (free, unauthenticated)
type ShodanClient struct {
	httpClient *http.Client
	cache      *IntelCache
	baseURL    string
}

// ShodanResponse represents the InternetDB API response
type ShodanResponse struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
	Hostnames []string `json:"hostnames"`
}

// ShodanResult contains processed Shodan data
type ShodanResult struct {
	IP        string    `json:"ip"`
	Ports     []int     `json:"ports"`
	Tags      []string  `json:"tags"`
	Vulns     []string  `json:"vulns"`
	Hostnames []string  `json:"hostnames"`
	HasVulns  bool      `json:"has_vulns"`
	RiskScore int       `json:"risk_score"`
	Timestamp time.Time `json:"timestamp"`
}

// NewShodanClient creates a new Shodan InternetDB client
func NewShodanClient() *ShodanClient {
	return &ShodanClient{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		cache:   NewIntelCache(1 * time.Hour),
		baseURL: "https://internetdb.shodan.io",
	}
}

// LookupIP queries Shodan InternetDB for IP information
func (c *ShodanClient) LookupIP(ctx context.Context, ip string) (*ShodanResult, error) {
	// Check cache
	cacheKey := fmt.Sprintf("shodan:%s", ip)
	if cached, ok := c.cache.Get(cacheKey); ok {
		return cached.(*ShodanResult), nil
	}

	// Build request
	reqURL := fmt.Sprintf("%s/%s", c.baseURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Shodan returns 404 for IPs with no data
	if resp.StatusCode == http.StatusNotFound {
		result := &ShodanResult{
			IP:        ip,
			Ports:     []int{},
			Tags:      []string{},
			Vulns:     []string{},
			Timestamp: time.Now(),
		}
		c.cache.Set(cacheKey, result)
		return result, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp ShodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process result
	result := &ShodanResult{
		IP:        apiResp.IP,
		Ports:     apiResp.Ports,
		Tags:      apiResp.Tags,
		Vulns:     apiResp.Vulns,
		Hostnames: apiResp.Hostnames,
		HasVulns:  len(apiResp.Vulns) > 0,
		Timestamp: time.Now(),
	}

	// Calculate risk score
	result.RiskScore = calculateShodanRisk(result)

	// Cache result
	c.cache.Set(cacheKey, result)

	return result, nil
}

func calculateShodanRisk(result *ShodanResult) int {
	score := 0

	// Points for CVEs
	score += len(result.Vulns) * 10

	// Points for exposed services
	for _, port := range result.Ports {
		switch port {
		case 22, 3389: // SSH, RDP
			score += 2
		case 21, 23, 25: // FTP, Telnet, SMTP
			score += 5
		case 3306, 5432, 6379, 27017: // Databases
			score += 8
		case 2375, 10250: // Docker, Kubernetes
			score += 10
		default:
			score += 1
		}
	}

	// Risky tags
	for _, tag := range result.Tags {
		switch tag {
		case "vpn", "proxy":
			score += 3
		case "compromised":
			score += 20
		}
	}

	return score
}

// ============================================================================
// Certificate Transparency Client
// ============================================================================

// CTClient queries certificate transparency logs
type CTClient struct {
	httpClient *http.Client
	cache      *IntelCache
}

// CTResponse represents Certificate Transparency search response
type CTResponse struct {
	Data []struct {
		ID             int    `json:"id"`
		LogID          string `json:"log_id"`
		CertID         string `json:"cert_id"`
		EntryTimestamp string `json:"entry_timestamp"`
		NotBefore      string `json:"not_before"`
		NotAfter       string `json:"not_after"`
		SerialNumber   string `json:"serial_number"`
		Subject        struct {
			CN string   `json:"CN"`
			O  string   `json:"O"`
			OU []string `json:"OU"`
			C  string   `json:"C"`
			ST string   `json:"ST"`
			L  string   `json:"L"`
		} `json:"subject"`
		SAN []string `json:"san"`
	} `json:"data"`
}

// CTResult contains processed certificate transparency data
type CTResult struct {
	Domain     string    `json:"domain"`
	Count      int       `json:"count"`
	Subdomains []string  `json:"subdomains"`
	Issuers    []string  `json:"issuers"`
	Timestamp  time.Time `json:"timestamp"`
}

// NewCTClient creates a new Certificate Transparency client
func NewCTClient() *CTClient {
	return &CTClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: NewIntelCache(6 * time.Hour),
	}
}

// QueryDomain queries certificate transparency logs for a domain
func (c *CTClient) QueryDomain(ctx context.Context, domain string) (*CTResult, error) {
	// Check cache
	cacheKey := fmt.Sprintf("ct:%s", domain)
	if cached, ok := c.cache.Get(cacheKey); ok {
		return cached.(*CTResult), nil
	}

	// Use crt.sh API (free, no auth required)
	reqURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Parse response
	var entries []struct {
		IssuerCaID     int    `json:"issuer_ca_id"`
		IssuerName     string `json:"issuer_name"`
		CommonName     string `json:"common_name"`
		NameValue      string `json:"name_value"`
		ID             int64  `json:"id"`
		EntryTimestamp string `json:"entry_timestamp"`
		NotBefore      string `json:"not_before"`
		NotAfter       string `json:"not_after"`
		SerialNumber   string `json:"serial_number"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process results
	result := &CTResult{
		Domain:     domain,
		Count:      len(entries),
		Subdomains: []string{},
		Issuers:    []string{},
		Timestamp:  time.Now(),
	}

	// Extract unique subdomains and issuers
	subdomainSet := make(map[string]bool)
	issuerSet := make(map[string]bool)

	for _, entry := range entries {
		if entry.NameValue != "" {
			subdomainSet[entry.NameValue] = true
		}
		if entry.IssuerName != "" {
			issuerSet[entry.IssuerName] = true
		}
	}

	for sub := range subdomainSet {
		result.Subdomains = append(result.Subdomains, sub)
	}
	for issuer := range issuerSet {
		result.Issuers = append(result.Issuers, issuer)
	}

	// Cache result
	c.cache.Set(cacheKey, result)

	return result, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func sha256String(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// ============================================================================
// Intel Manager
// ============================================================================

// IntelManager orchestrates all threat intelligence sources
type IntelManager struct {
	AbuseIPDB *AbuseIPDBClient
	URLhaus   *URLhausClient
	NVD       *NVDClient
	Shodan    *ShodanClient
	CT        *CTClient
}

// NewIntelManager creates a new intel manager with all clients
func NewIntelManager() *IntelManager {
	return &IntelManager{
		AbuseIPDB: NewAbuseIPDBClient(),
		URLhaus:   NewURLhausClient(),
		NVD:       NewNVDClient(),
		Shodan:    NewShodanClient(),
		CT:        NewCTClient(),
	}
}

// GetAvailableSources returns list of configured sources
func (m *IntelManager) GetAvailableSources() []string {
	sources := []string{"shodan", "urlhaus", "nvd", "cert_transparency"}
	if m.AbuseIPDB.IsConfigured() {
		sources = append(sources, "abuseipdb")
	}
	return sources
}
