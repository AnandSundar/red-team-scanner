package utils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
}

// Get returns the first value of a header (case-insensitive)
func (r *HTTPResponse) Get(key string) string {
	return r.Headers.Get(key)
}

// Values returns all values of a header
func (r *HTTPResponse) Values(key string) []string {
	return r.Headers.Values(key)
}

// Has checks if a header exists
func (r *HTTPResponse) Has(key string) bool {
	return r.Get(key) != ""
}

// HTTPClient is a wrapper around http.Client with enhanced features
type HTTPClient struct {
	client          *http.Client
	timeout         time.Duration
	followRedirects bool
	maxRedirects    int
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	jar, _ := cookiejar.New(nil)
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeout:         timeout,
		followRedirects: false,
		maxRedirects:    10,
	}
}

// NewHTTPClientWithRedirects creates an HTTP client that follows redirects
func NewHTTPClientWithRedirects(timeout time.Duration, maxRedirects int) *HTTPClient {
	jar, _ := cookiejar.New(nil)
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("max redirects exceeded")
				}
				return nil
			},
		},
		timeout:         timeout,
		followRedirects: true,
		maxRedirects:    maxRedirects,
	}
}

// SetFollowRedirects enables or disables redirect following
func (c *HTTPClient) SetFollowRedirects(follow bool) {
	c.followRedirects = follow
	if follow {
		c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.maxRedirects {
				return fmt.Errorf("max redirects exceeded")
			}
			return nil
		}
	} else {
		c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
}

// Do executes an HTTP request
func (c *HTTPClient) Do(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
	start := time.Now()

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = strings.NewReader(string(req.Body))
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "*/*")
	}

	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Read body with limit (10MB max)
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	return &HTTPResponse{
		StatusCode: httpResp.StatusCode,
		Headers:    httpResp.Header,
		Body:       body,
		Duration:   time.Since(start),
	}, nil
}

// Get performs a GET request
func (c *HTTPClient) Get(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error) {
	return c.Do(ctx, &HTTPRequest{
		Method:  http.MethodGet,
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (c *HTTPClient) Post(ctx context.Context, url string, headers map[string]string, body []byte) (*HTTPResponse, error) {
	return c.Do(ctx, &HTTPRequest{
		Method:  http.MethodPost,
		URL:     url,
		Headers: headers,
		Body:    body,
	})
}

// Head performs a HEAD request
func (c *HTTPClient) Head(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error) {
	return c.Do(ctx, &HTTPRequest{
		Method:  http.MethodHead,
		URL:     url,
		Headers: headers,
	})
}

// Options performs an OPTIONS request
func (c *HTTPClient) Options(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error) {
	return c.Do(ctx, &HTTPRequest{
		Method:  http.MethodOptions,
		URL:     url,
		Headers: headers,
	})
}

// ProbeResult contains comprehensive probing information
type ProbeResult struct {
	URL          string
	StatusCode   int
	Headers      http.Header
	Body         []byte
	Title        string
	Server       string
	Technologies []string
	ResponseTime time.Duration
	Error        error
}

// ExtractTitle extracts the title from HTML
func ExtractTitle(body []byte) string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return ""
	}

	var title string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			if n.FirstChild != nil {
				title = strings.TrimSpace(n.FirstChild.Data)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return title
}

// ExtractMetaTags extracts meta tags from HTML
func ExtractMetaTags(body []byte) map[string]string {
	meta := make(map[string]string)

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return meta
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			var name, content string
			for _, attr := range n.Attr {
				switch attr.Key {
				case "name", "property":
					name = attr.Val
				case "content":
					content = attr.Val
				}
			}
			if name != "" && content != "" {
				meta[name] = content
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return meta
}

// IsSuccess checks if status code indicates success
func IsSuccess(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// IsRedirect checks if status code indicates redirect
func IsRedirect(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

// IsClientError checks if status code indicates client error
func IsClientError(statusCode int) bool {
	return statusCode >= 400 && statusCode < 500
}

// IsServerError checks if status code indicates server error
func IsServerError(statusCode int) bool {
	return statusCode >= 500 && statusCode < 600
}

// BuildURL builds a URL from components
func BuildURL(scheme, host string, port int, path string) string {
	if path == "" {
		path = "/"
	}

	// Don't include default ports
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s%s", scheme, host, path)
	}

	return fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
}

// ParseContentType parses the Content-Type header
func ParseContentType(contentType string) (string, map[string]string) {
	parts := strings.Split(contentType, ";")
	mimeType := strings.TrimSpace(strings.ToLower(parts[0]))

	params := make(map[string]string)
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	return mimeType, params
}
