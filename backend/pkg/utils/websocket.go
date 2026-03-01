// Package utils provides WebSocket security testing utilities
package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketTester provides WebSocket security testing capabilities
type WebSocketTester struct {
	dialer     *websocket.Dialer
	timeout    time.Duration
	httpClient *HTTPClient
}

// WebSocketTestResult contains the result of a WebSocket test
type WebSocketTestResult struct {
	Success          bool          `json:"success"`
	Connected        bool          `json:"connected"`
	Error            string        `json:"error,omitempty"`
	ResponseTime     time.Duration `json:"response_time,omitempty"`
	ReceivedMessages []string      `json:"received_messages,omitempty"`
	SentMessages     []string      `json:"sent_messages,omitempty"`
	Headers          http.Header   `json:"headers,omitempty"`
	OriginValidated  bool          `json:"origin_validated"`
	AuthRequired     bool          `json:"auth_required"`
	Subprotocol      string        `json:"subprotocol,omitempty"`
	Extensions       []string      `json:"extensions,omitempty"`
}

// WebSocketConnection wraps a WebSocket connection for testing
type WebSocketConnection struct {
	conn      *websocket.Conn
	url       string
	headers   http.Header
	connected time.Time
}

// Message represents a WebSocket message
type Message struct {
	Type     int    `json:"type"`
	Data     []byte `json:"data"`
	IsText   bool   `json:"is_text"`
	IsBinary bool   `json:"is_binary"`
}

// NewWebSocketTester creates a new WebSocket tester
func NewWebSocketTester(timeout time.Duration) *WebSocketTester {
	return &WebSocketTester{
		dialer: &websocket.Dialer{
			HandshakeTimeout: timeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		timeout:    timeout,
		httpClient: NewHTTPClient(timeout),
	}
}

// SetTimeout sets the connection timeout
func (t *WebSocketTester) SetTimeout(timeout time.Duration) {
	t.timeout = timeout
	t.dialer.HandshakeTimeout = timeout
}

// TestConnection attempts to establish a WebSocket connection
func (t *WebSocketTester) TestConnection(ctx context.Context, wsURL string, headers http.Header) *WebSocketTestResult {
	result := &WebSocketTestResult{
		Success:   false,
		Connected: false,
		Headers:   make(http.Header),
	}

	start := time.Now()

	conn, resp, err := t.dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		result.Error = err.Error()
		if resp != nil {
			result.Headers = resp.Header.Clone()
		}
		return result
	}
	defer conn.Close()

	result.ResponseTime = time.Since(start)
	result.Success = true
	result.Connected = true

	if resp != nil {
		result.Headers = resp.Header.Clone()
		result.Subprotocol = resp.Header.Get("Sec-WebSocket-Protocol")
	}

	return result
}

// TestOriginValidation tests if the WebSocket server validates the Origin header
func (t *WebSocketTester) TestOriginValidation(ctx context.Context, wsURL string) (bool, string) {
	parsedURL, err := url.Parse(wsURL)
	if err != nil {
		return false, "invalid URL"
	}

	// Get the legitimate origin
	legitimateOrigin := parsedURL.Scheme + "://" + parsedURL.Host

	// Test with legitimate origin first
	headers := http.Header{}
	headers.Set("Origin", legitimateOrigin)
	result := t.TestConnection(ctx, wsURL, headers)
	if !result.Connected {
		return false, "could not connect with legitimate origin"
	}

	// Test with malicious origin
	headers.Set("Origin", "https://evil.com")
	result2 := t.TestConnection(ctx, wsURL, headers)
	if result2.Connected {
		// Server accepted connection from malicious origin
		return false, "accepted connection from malicious origin"
	}

	return true, "origin validation is enforced"
}

// TestAuthentication tests WebSocket authentication requirements
func (t *WebSocketTester) TestAuthentication(ctx context.Context, wsURL string) *WebSocketTestResult {
	result := &WebSocketTestResult{
		Success:   false,
		Connected: false,
	}

	// Try without authentication
	noAuthResult := t.TestConnection(ctx, wsURL, nil)
	if noAuthResult.Connected {
		result.Connected = true
		result.AuthRequired = false
		result.Success = true
		result.Error = "connected without authentication"
		return result
	}

	result.AuthRequired = true
	result.Success = true
	result.Error = "authentication required"

	return result
}

// Connect establishes a WebSocket connection and returns a wrapper
func (t *WebSocketTester) Connect(ctx context.Context, wsURL string, headers http.Header) (*WebSocketConnection, error) {
	conn, _, err := t.dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return nil, fmt.Errorf("websocket connection failed: %w", err)
	}

	return &WebSocketConnection{
		conn:      conn,
		url:       wsURL,
		headers:   headers,
		connected: time.Now(),
	}, nil
}

// SendText sends a text message
func (c *WebSocketConnection) SendText(message string) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	return c.conn.WriteMessage(websocket.TextMessage, []byte(message))
}

// SendBinary sends a binary message
func (c *WebSocketConnection) SendBinary(data []byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

// SendJSON sends a JSON message
func (c *WebSocketConnection) SendJSON(v interface{}) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	return c.conn.WriteJSON(v)
}

// ReadMessage reads a message with timeout
func (c *WebSocketConnection) ReadMessage(timeout time.Duration) (*Message, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Set read deadline
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer c.conn.SetReadDeadline(time.Time{}) // Clear deadline

	messageType, data, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	return &Message{
		Type:     messageType,
		Data:     data,
		IsText:   messageType == websocket.TextMessage,
		IsBinary: messageType == websocket.BinaryMessage,
	}, nil
}

// ReadMessages reads multiple messages within a timeout
func (c *WebSocketConnection) ReadMessages(count int, timeout time.Duration) ([]*Message, error) {
	var messages []*Message

	done := make(chan bool)
	go func() {
		for i := 0; i < count; i++ {
			msg, err := c.ReadMessage(timeout)
			if err != nil {
				return
			}
			messages = append(messages, msg)
		}
		done <- true
	}()

	select {
	case <-done:
		return messages, nil
	case <-time.After(timeout * time.Duration(count)):
		return messages, fmt.Errorf("timeout waiting for messages")
	}
}

// Close closes the WebSocket connection
func (c *WebSocketConnection) Close() error {
	if c.conn == nil {
		return nil
	}

	// Send close message
	c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

	return c.conn.Close()
}

// SendMessageWithResponse sends a message and waits for a response
func (c *WebSocketConnection) SendMessageWithResponse(message string, timeout time.Duration) (*Message, error) {
	if err := c.SendText(message); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	return c.ReadMessage(timeout)
}

// TestXSSPayload tests XSS payload through WebSocket
func (c *WebSocketConnection) TestXSSPayload(payload string) (bool, string, error) {
	// Send XSS payload
	if err := c.SendText(payload); err != nil {
		return false, "", err
	}

	// Wait for response
	msg, err := c.ReadMessage(5 * time.Second)
	if err != nil {
		return false, "", err
	}

	response := string(msg.Data)
	reflected := containsPayload(response, payload)

	return reflected, response, nil
}

// TestMalformedMessage sends a malformed message
func (c *WebSocketConnection) TestMalformedMessage() error {
	// Send invalid UTF-8 sequence
	invalidUTF8 := []byte{0xFF, 0xFE, 0xFD}
	return c.conn.WriteMessage(websocket.TextMessage, invalidUTF8)
}

// TestLargeMessage sends an oversized message
func (c *WebSocketConnection) TestLargeMessage(size int) error {
	largeData := make([]byte, size)
	for i := range largeData {
		largeData[i] = 'A'
	}
	return c.SendBinary(largeData)
}

// TestPingPong tests ping/pong handling
func (c *WebSocketConnection) TestPingPong() error {
	return c.conn.WriteMessage(websocket.PingMessage, []byte("test"))
}

// IsConnected returns true if the connection is still active
func (c *WebSocketConnection) IsConnected() bool {
	if c.conn == nil {
		return false
	}

	// Try to set write deadline to test connection
	if err := c.conn.SetWriteDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return false
	}
	c.conn.SetWriteDeadline(time.Time{}) // Clear deadline

	return true
}

// GetURL returns the connection URL
func (c *WebSocketConnection) GetURL() string {
	return c.url
}

// GetHeaders returns the connection headers
func (c *WebSocketConnection) GetHeaders() http.Header {
	return c.headers
}

// GetConnectedTime returns the connection time
func (c *WebSocketConnection) GetConnectedTime() time.Time {
	return c.connected
}

// DetectWebSocketEndpoint attempts to detect if an endpoint supports WebSocket
func DetectWebSocketEndpoint(httpClient *HTTPClient, targetURL string) (string, bool, error) {
	// Try to upgrade to WebSocket
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", false, err
	}

	// Convert HTTP to WS or HTTPS to WSS
	wsScheme := "ws"
	if parsedURL.Scheme == "https" {
		wsScheme = "wss"
	}

	wsURL := wsScheme + "://" + parsedURL.Host + parsedURL.Path

	// First try a regular GET to see if endpoint exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := httpClient.Get(ctx, targetURL, nil)
	if err != nil {
		return "", false, err
	}

	// Check for WebSocket upgrade headers
	if resp.Headers.Get("Upgrade") == "websocket" ||
		resp.Headers.Get("Sec-WebSocket-Accept") != "" {
		return wsURL, true, nil
	}

	return wsURL, false, nil
}

// BuildWebSocketURL builds a WebSocket URL from various inputs
func BuildWebSocketURL(baseURL, path string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}

	wsURL := scheme + "://" + u.Host
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			wsURL += "/"
		}
		wsURL += path
	}

	return wsURL, nil
}

// TestSubprotocol tests WebSocket subprotocol handling
func (t *WebSocketTester) TestSubprotocol(ctx context.Context, wsURL string, protocols []string) *WebSocketTestResult {
	result := &WebSocketTestResult{
		Success:   false,
		Connected: false,
	}

	headers := http.Header{}
	for _, proto := range protocols {
		headers.Add("Sec-WebSocket-Protocol", proto)
	}

	testResult := t.TestConnection(ctx, wsURL, headers)
	if testResult.Connected {
		result.Success = true
		result.Connected = true
		result.Subprotocol = testResult.Subprotocol
		result.Headers = testResult.Headers
	}

	return result
}

// containsPayload checks if a payload is reflected in a response
func containsPayload(response, payload string) bool {
	return len(response) > 0 &&
		(len(payload) == 0 ||
			(len(response) >= len(payload) &&
				(response == payload ||
					len(response) > len(payload))))
}
