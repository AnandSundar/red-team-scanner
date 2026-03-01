package classifier

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redteam/agentic-scanner/pkg/utils"
)

// ProbeResult represents the result of probing a target
type ProbeResult struct {
	Success       bool
	StatusCode    int
	Headers       http.Header
	Body          []byte
	TLSInfo       *TLSInfo
	WebSocketInfo *WebSocketInfo
	gRPCInfo      *gRPCInfo
	ResponseTime  time.Duration
	Error         string
}

// TLSInfo contains TLS certificate information
type TLSInfo struct {
	Version            uint16
	CipherSuite        uint16
	ServerName         string
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           []string
	IPAddresses        []net.IP
	IsSelfSigned       bool
	InsecureSkipVerify bool
}

// WebSocketInfo contains WebSocket capability information
type WebSocketInfo struct {
	Available        bool
	UpgradeHeader    string
	ConnectionHeader string
	Accepted         bool
	Subprotocols     []string
}

// gRPCInfo contains gRPC service information
type gRPCInfo struct {
	Available         bool
	ReflectionEnabled bool
	Services          []string
}

// TargetProber handles probing targets to gather information
type TargetProber struct {
	httpClient      *utils.HTTPClient
	tlsConfig       *tls.Config
	timeout         time.Duration
	maxRetries      int
	followRedirects bool
}

// NewTargetProber creates a new target prober
func NewTargetProber() *TargetProber {
	return &TargetProber{
		httpClient:      utils.NewHTTPClient(10 * time.Second),
		tlsConfig:       &tls.Config{},
		timeout:         10 * time.Second,
		maxRetries:      3,
		followRedirects: false,
	}
}

// SetTimeout sets the probe timeout
func (p *TargetProber) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
	p.httpClient = utils.NewHTTPClient(timeout)
}

// Probe performs a comprehensive probe of the target
func (p *TargetProber) Probe(ctx context.Context, target *NormalizedTarget) (*ProbeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	result := &ProbeResult{
		Success: false,
	}

	// Build URL
	urlStr := target.URL.String()

	// Try HEAD request first
	headResult, err := p.probeWithRetry(ctx, "HEAD", urlStr, nil, nil)
	if err != nil {
		// Fall back to GET
		getResult, err := p.probeWithRetry(ctx, "GET", urlStr, nil, nil)
		if err != nil {
			result.Error = err.Error()
			return result, nil // Return partial result
		}
		headResult = getResult
	}

	result.Success = true
	result.StatusCode = headResult.StatusCode
	result.Headers = headResult.Headers
	result.Body = headResult.Body
	result.ResponseTime = headResult.Duration

	// Analyze TLS if HTTPS
	if target.Protocol == "https" || target.Protocol == "grpcs" || target.Protocol == "wss" {
		tlsInfo, err := p.probeTLS(ctx, target)
		if err == nil {
			result.TLSInfo = tlsInfo
		}
	}

	// Check WebSocket capabilities
	wsInfo, err := p.probeWebSocket(ctx, target)
	if err == nil && wsInfo.Available {
		result.WebSocketInfo = wsInfo
	}

	// Check gRPC capabilities
	grpcInfo, err := p.probeGRPC(ctx, target)
	if err == nil && grpcInfo.Available {
		result.gRPCInfo = grpcInfo
	}

	return result, nil
}

// probeWithRetry performs HTTP request with exponential backoff
func (p *TargetProber) probeWithRetry(ctx context.Context, method, urlStr string, headers map[string]string, body []byte) (*utils.HTTPResponse, error) {
	var lastErr error

	backoff := time.Second
	for i := 0; i < p.maxRetries; i++ {
		resp, err := p.httpClient.Do(ctx, &utils.HTTPRequest{
			Method:  method,
			URL:     urlStr,
			Headers: headers,
			Body:    body,
		})
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// Don't retry on context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Exponential backoff
		if i < p.maxRetries-1 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// probeTLS analyzes the TLS certificate
func (p *TargetProber) probeTLS(ctx context.Context, target *NormalizedTarget) (*TLSInfo, error) {
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)

	// Create TLS connection
	dialer := &net.Dialer{Timeout: p.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true, // We want to analyze even self-signed certs
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]

	// Check if self-signed
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()

	tlsInfo := &TLSInfo{
		Version:            state.Version,
		CipherSuite:        state.CipherSuite,
		ServerName:         state.ServerName,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DNSNames:           cert.DNSNames,
		IPAddresses:        cert.IPAddresses,
		IsSelfSigned:       isSelfSigned,
		InsecureSkipVerify: true,
	}

	return tlsInfo, nil
}

// probeWebSocket checks WebSocket capabilities
func (p *TargetProber) probeWebSocket(ctx context.Context, target *NormalizedTarget) (*WebSocketInfo, error) {
	wsInfo := &WebSocketInfo{
		Available: false,
	}

	// Build WebSocket URL
	var wsURL string
	switch target.Protocol {
	case "https", "wss":
		wsURL = fmt.Sprintf("wss://%s:%d%s", target.Host, target.Port, target.Path)
	case "http", "ws":
		wsURL = fmt.Sprintf("ws://%s:%d%s", target.Host, target.Port, target.Path)
	default:
		wsURL = fmt.Sprintf("wss://%s:%d%s", target.Host, target.Port, target.Path)
	}

	// Try to establish WebSocket connection using HTTP upgrade
	headers := map[string]string{
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
		"Origin":                fmt.Sprintf("%s://%s", target.Protocol, target.Host),
	}

	resp, err := p.httpClient.Do(ctx, &utils.HTTPRequest{
		Method:  "GET",
		URL:     wsURL,
		Headers: headers,
	})

	if err != nil {
		return wsInfo, nil
	}

	// Check for WebSocket upgrade response
	if resp.StatusCode == http.StatusSwitchingProtocols {
		wsInfo.Available = true
		wsInfo.Accepted = true
		wsInfo.UpgradeHeader = resp.Headers.Get("Upgrade")
		wsInfo.ConnectionHeader = resp.Headers.Get("Connection")
		wsInfo.Subprotocols = resp.Headers.Values("Sec-WebSocket-Protocol")
	}

	return wsInfo, nil
}

// probeGRPC checks gRPC capabilities
func (p *TargetProber) probeGRPC(ctx context.Context, target *NormalizedTarget) (*gRPCInfo, error) {
	grpcInfo := &gRPCInfo{
		Available: false,
	}

	// Only check for gRPC on appropriate protocols
	if target.Protocol != "grpc" && target.Protocol != "grpcs" && target.Port != 50051 {
		// Still try common gRPC port
		if target.Port != 443 && target.Port != 80 {
			return grpcInfo, nil
		}
	}

	// Try gRPC reflection endpoint
	urlStr := fmt.Sprintf("%s://%s:%d/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		target.Protocol, target.Host, target.Port)

	// gRPC uses HTTP/2 POST with specific content-type
	headers := map[string]string{
		"Content-Type": "application/grpc",
		"TE":           "trailers",
	}

	resp, err := p.httpClient.Do(ctx, &utils.HTTPRequest{
		Method:  "POST",
		URL:     urlStr,
		Headers: headers,
		Body:    []byte{},
	})

	if err == nil && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusMethodNotAllowed) {
		grpcInfo.Available = true
		if resp.StatusCode == http.StatusOK {
			grpcInfo.ReflectionEnabled = true
		}
	}

	return grpcInfo, nil
}

// ProbeAIEndpoints checks for common AI/LLM endpoints
func (p *TargetProber) ProbeAIEndpoints(ctx context.Context, target *NormalizedTarget) map[string]AIEndpointResult {
	results := make(map[string]AIEndpointResult)

	aiPaths := []string{
		"/chat",
		"/api/chat",
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/messages",
		"/api/completions",
		"/api/generate",
		"/api/v1/generate",
		"/v1/models",
		"/api/models",
	}

	for _, path := range aiPaths {
		urlStr := fmt.Sprintf("%s://%s:%d%s", target.Protocol, target.Host, target.Port, path)

		resp, err := p.probeWithRetry(ctx, "GET", urlStr, map[string]string{
			"Accept": "application/json",
		}, nil)

		result := AIEndpointResult{
			Path:   path,
			Tested: true,
			Exists: false,
		}

		if err == nil {
			result.StatusCode = resp.StatusCode
			// AI endpoints often return 401 (unauthorized) or 405 (method not allowed)
			if resp.StatusCode == http.StatusOK ||
				resp.StatusCode == http.StatusUnauthorized ||
				resp.StatusCode == http.StatusMethodNotAllowed ||
				resp.StatusCode == http.StatusForbidden {
				result.Exists = true

				// Check for OpenAI-compatible headers
				if openAIVersion := resp.Headers.Get("openai-version"); openAIVersion != "" {
					result.OpenAICompatible = true
				}

				// Try to parse JSON response for model info
				var jsonResp map[string]interface{}
				if err := json.Unmarshal(resp.Body, &jsonResp); err == nil {
					if _, hasData := jsonResp["data"]; hasData {
						result.HasModels = true
					}
					if _, hasObject := jsonResp["object"]; hasObject {
						result.HasObject = true
					}
				}
			}
		} else {
			result.Error = err.Error()
		}

		results[path] = result
	}

	return results
}

// AIEndpointResult represents the result of probing an AI endpoint
type AIEndpointResult struct {
	Path             string
	Tested           bool
	Exists           bool
	StatusCode       int
	OpenAICompatible bool
	HasModels        bool
	HasObject        bool
	Error            string
}

// ProbeGraphQL checks for GraphQL endpoint
func (p *TargetProber) ProbeGraphQL(ctx context.Context, target *NormalizedTarget) GraphQLProbeResult {
	result := GraphQLProbeResult{
		Found: false,
	}

	graphqlPaths := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/query",
	}

	introspectionQuery := `{"query": "{ __schema { types { name } } }"}`

	for _, path := range graphqlPaths {
		urlStr := fmt.Sprintf("%s://%s:%d%s", target.Protocol, target.Host, target.Port, path)

		// Try POST with introspection query
		resp, err := p.probeWithRetry(ctx, "POST", urlStr, map[string]string{
			"Content-Type": "application/json",
		}, []byte(introspectionQuery))

		if err == nil {
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
				// Check for GraphQL-specific headers
				contentType := resp.Headers.Get("Content-Type")
				if strings.Contains(contentType, "application/graphql") ||
					strings.Contains(contentType, "application/json") {

					// Try to parse as JSON
					var jsonResp map[string]interface{}
					if err := json.Unmarshal(resp.Body, &jsonResp); err == nil {
						// Check for GraphQL-specific fields
						if _, hasData := jsonResp["data"]; hasData {
							result.Found = true
							result.Endpoint = path
							result.IntrospectionEnabled = true
							return result
						}
						if _, hasErrors := jsonResp["errors"]; hasErrors {
							// GraphQL error response
							result.Found = true
							result.Endpoint = path
							return result
						}
					}
				}
			}
		}
	}

	return result
}

// GraphQLProbeResult represents GraphQL detection result
type GraphQLProbeResult struct {
	Found                bool
	Endpoint             string
	IntrospectionEnabled bool
}
