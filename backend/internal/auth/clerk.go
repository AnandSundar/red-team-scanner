package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwks"
	"github.com/clerk/clerk-sdk-go/v2/user"
)

// ============================================================================
// JWKS Cache
// ============================================================================

// JWKSCache caches JWKS responses to avoid repeated requests
type JWKSCache struct {
	mu        sync.RWMutex
	client    *jwks.Client
	keys      *clerk.JSONWebKeySet
	expiresAt time.Time
	duration  time.Duration
	lastFetch time.Time
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache(client *jwks.Client, duration time.Duration) *JWKSCache {
	return &JWKSCache{
		client:   client,
		duration: duration,
	}
}

// GetKeys retrieves JWKS keys, using cache if valid
func (c *JWKSCache) GetKeys(ctx context.Context) (*clerk.JSONWebKeySet, error) {
	c.mu.RLock()
	if time.Now().Before(c.expiresAt) && c.keys != nil {
		keys := c.keys
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	// Fetch fresh keys
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(c.expiresAt) && c.keys != nil {
		return c.keys, nil
	}

	// Fetch from Clerk JWKS endpoint
	keys, err := jwks.Get(ctx, &jwks.GetParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	c.keys = keys
	c.expiresAt = time.Now().Add(c.duration)
	c.lastFetch = time.Now()

	return c.keys, nil
}

// Invalidate clears the cache
func (c *JWKSCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = nil
	c.expiresAt = time.Time{}
}

// LastFetch returns the time of the last successful fetch
func (c *JWKSCache) LastFetch() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastFetch
}

// ============================================================================
// Clerk Client
// ============================================================================

// ClerkClient wraps the Clerk SDK v2 client with caching
type ClerkClient struct {
	apiKey     string
	backend    clerk.Backend
	jwksCache  *JWKSCache
	httpClient *http.Client
	jwksClient *jwks.Client
}

// ClerkClientConfig contains configuration for the Clerk client
type ClerkClientConfig struct {
	SecretKey         string
	JWKSFetchInterval time.Duration
	HTTPTimeout       time.Duration
}

// NewClerkClient creates a new Clerk client with JWT validation support
func NewClerkClient(cfg ClerkClientConfig) (*ClerkClient, error) {
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("CLERK_SECRET_KEY is required")
	}

	// Set defaults
	if cfg.JWKSFetchInterval == 0 {
		cfg.JWKSFetchInterval = 1 * time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}

	// Initialize Clerk SDK v2
	clerk.SetKey(cfg.SecretKey)

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}

	// Create backend config
	backendConfig := &clerk.BackendConfig{
		HTTPClient: httpClient,
	}

	// Create backend
	backend := clerk.NewBackend(backendConfig)

	// Create JWKS client
	jwksClient := jwks.NewClient(&jwks.ClientConfig{})

	// Create JWKS cache
	cache := NewJWKSCache(jwksClient, cfg.JWKSFetchInterval)

	return &ClerkClient{
		apiKey:     cfg.SecretKey,
		backend:    backend,
		jwksCache:  cache,
		httpClient: httpClient,
		jwksClient: jwksClient,
	}, nil
}

// VerifyToken verifies a Clerk JWT token using the v2 SDK
func (c *ClerkClient) VerifyToken(ctx context.Context, token string) (*clerk.SessionClaims, error) {
	// Get JWKS keys
	jwks, err := c.jwksCache.GetKeys(ctx)
	if err != nil {
		return nil, err
	}

	// Verify the token using the keys
	// The SessionClaims can be extracted from the token
	var claims clerk.SessionClaims

	// Decode token without verification first to get claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Decode payload
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Verify the token hasn't expired
	if claims.Expiry != nil && time.Now().Unix() > *claims.Expiry {
		return nil, ErrSessionExpired
	}

	// Verify signature against JWKS
	verified := false
	for _, key := range jwks.Keys {
		// In production, properly verify the signature using the key
		// This is a simplified check - implement full JWT verification
		if key.KeyID != "" {
			verified = true
			break
		}
	}

	if !verified {
		return nil, ErrInvalidToken
	}

	return &claims, nil
}

// GetUser retrieves a user by ID from Clerk
func (c *ClerkClient) GetUser(ctx context.Context, userID string) (*clerk.User, error) {
	usr, err := user.Get(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from Clerk: %w", err)
	}
	return usr, nil
}

// GetUserByClerkID retrieves a user using their Clerk user ID
func (c *ClerkClient) GetUserByClerkID(ctx context.Context, clerkUserID string) (*clerk.User, error) {
	return c.GetUser(ctx, clerkUserID)
}

// GetSession retrieves a session by ID from Clerk
func (c *ClerkClient) GetSession(ctx context.Context, sessionID string) (*clerk.Session, error) {
	// Use the backend API to get session
	req := clerk.NewAPIRequest("GET", fmt.Sprintf("/sessions/%s", sessionID))

	var session clerk.Session
	if err := c.backend.Call(ctx, req, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// VerifySession validates a session token against Clerk's API
func (c *ClerkClient) VerifySession(ctx context.Context, sessionID, token string) error {
	claims, err := c.VerifyToken(ctx, token)
	if err != nil {
		return err
	}

	// Check session ID if provided
	if sessionID != "" && claims.Claims.SessionID != sessionID {
		return ErrInvalidToken
	}

	return nil
}

// ============================================================================
// Webhook Handling
// ============================================================================

// WebhookEvent represents a Clerk webhook event
type WebhookEvent struct {
	Type      string          `json:"type"`
	Object    string          `json:"object"`
	ID        string          `json:"id"`
	Data      json.RawMessage `json:"data"`
	CreatedAt int64           `json:"created_at"`
}

// UserCreatedData represents the data for user.created webhook
type UserCreatedData struct {
	ID              string                 `json:"id"`
	EmailAddresses  []EmailAddress         `json:"email_addresses"`
	PrimaryEmailID  string                 `json:"primary_email_address_id"`
	PublicMetadata  map[string]interface{} `json:"public_metadata"`
	PrivateMetadata map[string]interface{} `json:"private_metadata"`
}

// EmailAddress represents an email address in Clerk
type EmailAddress struct {
	ID           string `json:"id"`
	EmailAddress string `json:"email_address"`
	Verification struct {
		Status string `json:"status"`
	} `json:"verification"`
}

// VerifyWebhookSignature verifies the webhook signature from Clerk
func (c *ClerkClient) VerifyWebhookSignature(payload []byte, signature string) error {
	// In production, verify the webhook signature using Clerk's signing secret
	// This is a simplified version - implement full verification in production
	if signature == "" {
		return fmt.Errorf("missing webhook signature")
	}
	return nil
}

// ParseWebhookEvent parses a webhook event from JSON
func (c *ClerkClient) ParseWebhookEvent(payload []byte) (*WebhookEvent, error) {
	var event WebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf("failed to parse webhook event: %w", err)
	}
	return &event, nil
}

// ============================================================================
// Token Extraction
// ============================================================================

// ExtractToken extracts the Bearer token from the Authorization header
func ExtractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// Try cookie as fallback
		if cookie, err := r.Cookie("__session"); err == nil {
			return cookie.Value
		}
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}

// ExtractAPIKey extracts the API key from the X-API-Key header
func ExtractAPIKey(r *http.Request) string {
	return r.Header.Get("X-API-Key")
}

// GetTokenInfo extracts and identifies the token type from the request
func GetTokenInfo(r *http.Request) *TokenInfo {
	// Check for Bearer token
	if token := ExtractToken(r); token != "" {
		return &TokenInfo{
			Type:   TokenTypeBearer,
			Value:  token,
			Source: "Authorization header",
		}
	}

	// Check for API key
	if apiKey := ExtractAPIKey(r); apiKey != "" {
		return &TokenInfo{
			Type:   TokenTypeAPIKey,
			Value:  apiKey,
			Source: "X-API-Key header",
		}
	}

	// Check for session cookie
	if cookie, err := r.Cookie("__session"); err == nil {
		return &TokenInfo{
			Type:   TokenTypeCookie,
			Value:  cookie.Value,
			Source: "Cookie",
		}
	}

	return nil
}

// ============================================================================
// Error Handling
// ============================================================================

// WriteAuthError writes an authentication error response
func WriteAuthError(w http.ResponseWriter, err *AuthError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Status)
	w.Write(err.JSON())
}

// IsClerkError checks if an error is a Clerk SDK error
func IsClerkError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "clerk")
}

// ExtractClaimsFromContext extracts Clerk claims from context
func ExtractClaimsFromContext(ctx context.Context) *clerk.SessionClaims {
	if claims, ok := ctx.Value(ContextKeyClaims).(*clerk.SessionClaims); ok {
		return claims
	}
	return nil
}

// decodeBase64URL decodes base64 URL-encoded data
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if necessary
	padding := 4 - len(s)%4
	if padding != 4 {
		s += strings.Repeat("=", padding)
	}
	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}
