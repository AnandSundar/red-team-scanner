// Package utils provides utility functions for security testing
package utils

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/redteam/agentic-scanner/pkg/payloads"
)

// SecurityHTTPResponse extends HTTPResponse with additional metadata for security testing
type SecurityHTTPResponse struct {
	StatusCode   int
	Headers      http.Header
	Body         []byte
	URL          *url.URL
	RequestURL   string
	ResponseTime time.Duration
	RawRequest   string
	RawResponse  string
}

// SecurityHTTPClient is a specialized HTTP client for security testing
type SecurityHTTPClient struct {
	Client       *http.Client
	Timeout      time.Duration
	MaxRedirects int
	RateLimiter  *time.Ticker
}

// NewSecurityHTTPClient creates a new security testing HTTP client
func NewSecurityHTTPClient(timeout time.Duration, maxRedirects int) *SecurityHTTPClient {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if maxRedirects <= 0 {
		maxRedirects = 10
	}

	return &SecurityHTTPClient{
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Timeout:      timeout,
		MaxRedirects: maxRedirects,
	}
}

// SetRateLimit sets a rate limit for requests
func (c *SecurityHTTPClient) SetRateLimit(rps int) {
	if c.RateLimiter != nil {
		c.RateLimiter.Stop()
	}
	if rps > 0 {
		c.RateLimiter = time.NewTicker(time.Second / time.Duration(rps))
	}
}

// WaitForRateLimit waits for the rate limiter
func (c *SecurityHTTPClient) WaitForRateLimit() {
	if c.RateLimiter != nil {
		<-c.RateLimiter.C
	}
}

// Stop stops the rate limiter
func (c *SecurityHTTPClient) Stop() {
	if c.RateLimiter != nil {
		c.RateLimiter.Stop()
	}
}

// Request performs an HTTP request and returns detailed response
func (c *SecurityHTTPClient) Request(method, targetURL string, headers map[string]string, body []byte) (*SecurityHTTPResponse, error) {
	c.WaitForRateLimit()

	req, err := http.NewRequest(method, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "identity")

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	start := time.Now()
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	responseTime := time.Since(start)

	// Build raw request string
	rawRequest := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, req.URL.RequestURI())
	for key, values := range req.Header {
		for _, value := range values {
			rawRequest += fmt.Sprintf("%s: %s\r\n", key, value)
		}
	}
	rawRequest += "\r\n"
	if len(body) > 0 {
		rawRequest += string(body)
	}

	// Build raw response string
	rawResponse := fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status)
	for key, values := range resp.Header {
		for _, value := range values {
			rawResponse += fmt.Sprintf("%s: %s\r\n", key, value)
		}
	}
	rawResponse += "\r\n"
	if len(respBody) > 0 {
		rawResponse += string(respBody)
	}

	return &SecurityHTTPResponse{
		StatusCode:   resp.StatusCode,
		Headers:      resp.Header,
		Body:         respBody,
		URL:          resp.Request.URL,
		RequestURL:   targetURL,
		ResponseTime: responseTime,
		RawRequest:   rawRequest,
		RawResponse:  rawResponse,
	}, nil
}

// Get performs a GET request
func (c *SecurityHTTPClient) Get(targetURL string, headers map[string]string) (*SecurityHTTPResponse, error) {
	return c.Request("GET", targetURL, headers, nil)
}

// Post performs a POST request
func (c *SecurityHTTPClient) Post(targetURL string, headers map[string]string, body []byte) (*SecurityHTTPResponse, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	if headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	return c.Request("POST", targetURL, headers, body)
}

// Put performs a PUT request
func (c *SecurityHTTPClient) Put(targetURL string, headers map[string]string, body []byte) (*SecurityHTTPResponse, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	if headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/json"
	}
	return c.Request("PUT", targetURL, headers, body)
}

// Delete performs a DELETE request
func (c *SecurityHTTPClient) Delete(targetURL string, headers map[string]string) (*SecurityHTTPResponse, error) {
	return c.Request("DELETE", targetURL, headers, nil)
}

// IsWAFBlocked checks if response indicates WAF blocking
func IsWAFBlocked(resp *SecurityHTTPResponse) bool {
	wafIndicators := []string{
		"blocked",
		"forbidden",
		"access denied",
		"waf",
		"firewall",
		"security check",
		"captcha",
		"cloudflare",
		"incapsula",
		"akamai",
		"sucuri",
		"wordfence",
		"mod_security",
		"blocked by",
		"403 forbidden",
		"406 not acceptable",
		"429 too many requests",
		"503 service unavailable",
	}

	bodyStr := strings.ToLower(string(resp.Body))
	for _, indicator := range wafIndicators {
		if strings.Contains(bodyStr, indicator) {
			return true
		}
	}

	// Check for common WAF status codes
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
		return true
	}

	return false
}

// XSSDetector provides XSS detection functionality
type XSSDetector struct {
	patterns []*regexp.Regexp
}

// NewXSSDetector creates a new XSS detector
func NewXSSDetector() *XSSDetector {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>[^<]*alert\s*\(\s*1\s*\)`),
		regexp.MustCompile(`(?i)<[^>]+on\w+\s*=\s*["']?[^"']*alert`),
		regexp.MustCompile(`(?i)javascript:\s*alert`),
		regexp.MustCompile(`(?i)<svg[^>]*onload\s*=`),
		regexp.MustCompile(`(?i)<img[^>]*onerror\s*=`),
		regexp.MustCompile(`(?i)<[^>]+on\w+\s*=\s*["']?\s*alert`),
	}

	return &XSSDetector{patterns: patterns}
}

// Detect checks if XSS payload appears in response unencoded
func (d *XSSDetector) Detect(payload string, responseBody []byte) bool {
	// Check if payload appears exactly in response (unencoded)
	if bytes.Contains(responseBody, []byte(payload)) {
		return true
	}

	// Check with HTML entity decoding
	decoded := htmlDecode(string(responseBody))
	if strings.Contains(decoded, payload) {
		return true
	}

	// Check for reflected XSS patterns
	for _, pattern := range d.patterns {
		if pattern.Match(responseBody) {
			return true
		}
	}

	return false
}

// SQLiDetector provides SQL injection detection functionality
type SQLiDetector struct {
	patterns []*regexp.Regexp
}

// NewSQLiDetector creates a new SQLi detector
func NewSQLiDetector() *SQLiDetector {
	patterns := make([]*regexp.Regexp, 0, len(payloads.SQLiErrorPatterns))
	for _, pattern := range payloads.SQLiErrorPatterns {
		re, err := regexp.Compile(`(?i)` + pattern)
		if err == nil {
			patterns = append(patterns, re)
		}
	}

	return &SQLiDetector{patterns: patterns}
}

// Detect checks for SQL error messages in response
func (d *SQLiDetector) Detect(responseBody []byte) (bool, string) {
	bodyStr := string(responseBody)

	for _, pattern := range d.patterns {
		if match := pattern.FindString(bodyStr); match != "" {
			return true, match
		}
	}

	return false, ""
}

// htmlDecode decodes common HTML entities
func htmlDecode(s string) string {
	result := s
	result = strings.ReplaceAll(result, "<", "<")
	result = strings.ReplaceAll(result, ">", ">")
	result = strings.ReplaceAll(result, "&", "&")
	return result
}

// ExtractParameters extracts URL parameters from a URL
func ExtractParameters(targetURL string) (map[string]string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	for key, values := range u.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	return params, nil
}

// BuildURLWithParam builds a URL with a modified parameter
func BuildURLWithParam(targetURL, paramName, paramValue string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	query := u.Query()
	query.Set(paramName, paramValue)
	u.RawQuery = query.Encode()

	return u.String(), nil
}

// ExtractLinks extracts links from HTML content
func ExtractLinks(body []byte, baseURL string) []string {
	var links []string
	base, err := url.Parse(baseURL)
	if err != nil {
		return links
	}

	// Extract href attributes
	hrefRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := hrefRegex.FindAllSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := string(match[1])
			// Resolve relative URLs
			if u, err := base.Parse(link); err == nil {
				links = append(links, u.String())
			}
		}
	}

	// Extract action attributes (forms)
	actionRegex := regexp.MustCompile(`action=["']([^"']+)["']`)
	actionMatches := actionRegex.FindAllSubmatch(body, -1)

	for _, match := range actionMatches {
		if len(match) > 1 {
			link := string(match[1])
			if u, err := base.Parse(link); err == nil {
				links = append(links, u.String())
			}
		}
	}

	return links
}

// Form represents an HTML form
type Form struct {
	Action string
	Method string
	Fields map[string]string
}

// ExtractForms extracts form information from HTML content
func ExtractForms(body []byte, baseURL string) []Form {
	var forms []Form
	base, _ := url.Parse(baseURL)

	// Simple regex-based form extraction (in production, use a proper HTML parser)
	formRegex := regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["'][^>]*>(.*?)</form>`)
	matches := formRegex.FindAllSubmatch(body, -1)

	for _, match := range matches {
		form := Form{
			Fields: make(map[string]string),
		}

		if len(match) > 1 {
			action := string(match[1])
			if u, err := base.Parse(action); err == nil {
				form.Action = u.String()
			}
		}

		// Extract input fields
		inputRegex := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*>`)
		if len(match) > 2 {
			inputs := inputRegex.FindAllSubmatch(match[2], -1)
			for _, input := range inputs {
				if len(input) > 1 {
					fieldName := string(input[1])
					form.Fields[fieldName] = ""
				}
			}
		}

		forms = append(forms, form)
	}

	return forms
}

// CORSTester provides CORS vulnerability testing
type CORSTester struct {
	client *SecurityHTTPClient
}

// CORSTestResult contains CORS test results
type CORSTestResult struct {
	Vulnerable       bool
	AllowOrigin      string
	AllowCredentials bool
	AllowMethods     []string
	AllowHeaders     []string
	Severity         string
	Evidence         string
}

// NewCORSTester creates a new CORS tester
func NewCORSTester(client *SecurityHTTPClient) *CORSTester {
	return &CORSTester{client: client}
}

// Test performs CORS configuration tests
func (t *CORSTester) Test(targetURL string) (*CORSTestResult, error) {
	result := &CORSTestResult{
		Vulnerable: false,
	}

	// Test with evil origin
	headers := map[string]string{
		"Origin": "https://evil.com",
	}

	resp, err := t.client.Get(targetURL, headers)
	if err != nil {
		return nil, err
	}

	allowOrigin := resp.Headers.Get("Access-Control-Allow-Origin")
	allowCredentials := resp.Headers.Get("Access-Control-Allow-Credentials")

	result.AllowOrigin = allowOrigin

	// Check for wildcard with credentials (critical)
	if allowOrigin == "*" && strings.ToLower(allowCredentials) == "true" {
		result.Vulnerable = true
		result.AllowCredentials = true
		result.Severity = "critical"
		result.Evidence = "Wildcard Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true"
		return result, nil
	}

	// Check if evil.com is reflected (critical if credentials allowed)
	if strings.Contains(allowOrigin, "evil.com") {
		result.Vulnerable = true
		result.AllowOrigin = allowOrigin

		if strings.ToLower(allowCredentials) == "true" {
			result.AllowCredentials = true
			result.Severity = "critical"
			result.Evidence = "Arbitrary origin reflected with credentials allowed"
		} else {
			result.Severity = "medium"
			result.Evidence = "Arbitrary origin reflected without credentials"
		}
		return result, nil
	}

	// Check for null origin (high severity)
	if allowOrigin == "null" {
		result.Vulnerable = true
		result.Severity = "high"
		result.Evidence = "Null origin allowed - can be exploited via iframe sandbox"
		return result, nil
	}

	// Test with OPTIONS preflight
	preflightHeaders := map[string]string{
		"Origin":                        "https://evil.com",
		"Access-Control-Request-Method": "GET",
	}

	preflightResp, err := t.client.Request("OPTIONS", targetURL, preflightHeaders, nil)
	if err == nil {
		result.AllowMethods = parseHeaderList(preflightResp.Headers.Get("Access-Control-Allow-Methods"))
		result.AllowHeaders = parseHeaderList(preflightResp.Headers.Get("Access-Control-Allow-Headers"))
	}

	return result, nil
}

// parseHeaderList parses a comma-separated header list
func parseHeaderList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// IsSuccessStatus checks if the status code indicates success
func IsSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// IsRedirectStatus checks if the status code indicates a redirect
func IsRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

// IsClientErrorStatus checks if the status code indicates a client error
func IsClientErrorStatus(code int) bool {
	return code >= 400 && code < 500
}

// IsServerErrorStatus checks if the status code indicates a server error
func IsServerErrorStatus(code int) bool {
	return code >= 500 && code < 600
}
