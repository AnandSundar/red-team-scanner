package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/google/uuid"
)

// ============================================================================
// Middleware
// ============================================================================

// Middleware provides authentication middleware for the API
type Middleware struct {
	clerkClient *ClerkClient
	apiKeyStore APIKeyStore
	rateLimiter RateLimiter
}

// APIKeyStore interface for API key validation
type APIKeyStore interface {
	GetUserByAPIKey(ctx context.Context, apiKey string) (*User, error)
}

// RateLimiter interface for rate limiting
type RateLimiter interface {
	CheckLimit(ctx context.Context, userID uuid.UUID, limit RateLimit) (bool, error)
}

// MiddlewareConfig contains configuration for the middleware
type MiddlewareConfig struct {
	ClerkClient *ClerkClient
	APIKeyStore APIKeyStore
	RateLimiter RateLimiter
	AllowCORS   bool
	CORSOrigins []string
}

// NewMiddleware creates new auth middleware
func NewMiddleware(cfg MiddlewareConfig) *Middleware {
	return &Middleware{
		clerkClient: cfg.ClerkClient,
		apiKeyStore: cfg.APIKeyStore,
		rateLimiter: cfg.RateLimiter,
	}
}

// NewMiddlewareWithClient creates middleware with just a Clerk client (backward compatibility)
func NewMiddlewareWithClient(client *ClerkClient) *Middleware {
	return &Middleware{
		clerkClient: client,
	}
}

// ============================================================================
// RequireAuth Middleware
// ============================================================================

// RequireAuth ensures the request is authenticated
func (m *Middleware) RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle OPTIONS requests for CORS
			if r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// Development mode bypass - check for DEV_MODE env var
			if os.Getenv("DEV_MODE") == "true" {
				// Create a mock user for development
				devUser := &User{
					ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
					Email:     "dev@localhost",
					Tier:      TierEnterprise,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				ctx := context.WithValue(r.Context(), ContextKeyUser, devUser)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Get token info
			tokenInfo := GetTokenInfo(r)
			if tokenInfo == nil {
				WriteAuthError(w, ErrMissingToken)
				return
			}

			// Authenticate based on token type
			var user *User
			var claims *clerk.SessionClaims
			var err error

			switch tokenInfo.Type {
			case TokenTypeBearer, TokenTypeCookie:
				user, claims, err = m.authenticateJWT(r.Context(), tokenInfo.Value)
			case TokenTypeAPIKey:
				user, err = m.authenticateAPIKey(r.Context(), tokenInfo.Value)
			default:
				WriteAuthError(w, ErrInvalidToken)
				return
			}

			if err != nil {
				if authErr, ok := IsAuthError(err); ok {
					WriteAuthError(w, authErr)
					return
				}
				WriteAuthError(w, ErrInvalidToken)
				return
			}

			// Check rate limit if rate limiter is configured
			if m.rateLimiter != nil {
				allowed, err := m.rateLimiter.CheckLimit(r.Context(), user.ID, user.GetRateLimit())
				if err != nil || !allowed {
					WriteAuthError(w, ErrRateLimitExceeded)
					return
				}
			}

			// Set user and claims in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, ContextKeyUser, user)
			if claims != nil {
				ctx = context.WithValue(ctx, ContextKeyClaims, claims)
				if claims.Claims.SessionID != "" {
					ctx = context.WithValue(ctx, ContextKeySessionID, claims.Claims.SessionID)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authenticateJWT authenticates using JWT token
func (m *Middleware) authenticateJWT(ctx context.Context, token string) (*User, *clerk.SessionClaims, error) {
	if m.clerkClient == nil {
		return nil, nil, ErrInvalidToken
	}

	claims, err := m.clerkClient.VerifyToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	// Get user from Clerk
	clerkUser, err := m.clerkClient.GetUser(ctx, claims.Subject)
	if err != nil {
		return nil, nil, ErrUserNotFound
	}

	// Convert Clerk user to our User type
	user := convertClerkUser(clerkUser)

	return user, claims, nil
}

// authenticateAPIKey authenticates using API key
func (m *Middleware) authenticateAPIKey(ctx context.Context, apiKey string) (*User, error) {
	if m.apiKeyStore == nil {
		return nil, ErrInvalidAPIKey
	}

	user, err := m.apiKeyStore.GetUserByAPIKey(ctx, apiKey)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}

	// Check if user has API access
	if !user.HasFeature("api_access") {
		return nil, ErrInsufficientTier
	}

	return user, nil
}

// ============================================================================
// OptionalAuth Middleware
// ============================================================================

// OptionalAuth allows both authenticated and unauthenticated requests
// If a token is present and valid, the user is added to context
// If no token or invalid token, the request continues without user context
func (m *Middleware) OptionalAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle OPTIONS requests for CORS
			if r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			tokenInfo := GetTokenInfo(r)
			if tokenInfo == nil {
				// No token, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Try to authenticate but don't fail if it doesn't work
			var user *User
			var claims *clerk.SessionClaims
			var err error

			switch tokenInfo.Type {
			case TokenTypeBearer, TokenTypeCookie:
				user, claims, err = m.authenticateJWT(r.Context(), tokenInfo.Value)
			case TokenTypeAPIKey:
				user, err = m.authenticateAPIKey(r.Context(), tokenInfo.Value)
			}

			// Add to context only if authentication succeeded
			if err == nil && user != nil {
				ctx := r.Context()
				ctx = context.WithValue(ctx, ContextKeyUser, user)
				if claims != nil {
					ctx = context.WithValue(ctx, ContextKeyClaims, claims)
				}
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// RequireAPIKey Middleware
// ============================================================================

// RequireAPIKey ensures the request is authenticated with an API key
func (m *Middleware) RequireAPIKey() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle OPTIONS requests for CORS
			if r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// Development mode bypass - check for DEV_MODE env var
			if os.Getenv("DEV_MODE") == "true" {
				// Create a mock user for development
				devUser := &User{
					ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
					Email:     "dev@localhost",
					Tier:      TierEnterprise,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				ctx := context.WithValue(r.Context(), ContextKeyUser, devUser)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			apiKey := ExtractAPIKey(r)
			if apiKey == "" {
				WriteAuthError(w, ErrMissingAPIKey)
				return
			}

			user, err := m.authenticateAPIKey(r.Context(), apiKey)
			if err != nil {
				if authErr, ok := IsAuthError(err); ok {
					WriteAuthError(w, authErr)
					return
				}
				WriteAuthError(w, ErrInvalidAPIKey)
				return
			}

			// Check rate limit if rate limiter is configured
			if m.rateLimiter != nil {
				allowed, err := m.rateLimiter.CheckLimit(r.Context(), user.ID, user.GetRateLimit())
				if err != nil || !allowed {
					WriteAuthError(w, ErrRateLimitExceeded)
					return
				}
			}

			// Set user in context
			ctx := context.WithValue(r.Context(), ContextKeyUser, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
// RequireAdmin Middleware
// ============================================================================

// RequireAdmin ensures the user has admin privileges
func (m *Middleware) RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				WriteAuthError(w, ErrMissingToken)
				return
			}

			// Check admin role in metadata or database
			// This is a placeholder - implement based on your admin logic
			isAdmin := false
			if user.Tier == TierEnterprise {
				// Check if user has admin flag in metadata
				isAdmin = false // Replace with actual check
			}

			if !isAdmin {
				WriteAuthError(w, ErrUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// RequireTier Middleware
// ============================================================================

// RequireTier creates middleware that requires a specific tier
func (m *Middleware) RequireTier(tier UserTier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				WriteAuthError(w, ErrMissingToken)
				return
			}

			if !hasTierAccess(user.Tier, tier) {
				WriteAuthError(w, ErrInsufficientTier)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// hasTierAccess checks if user tier has access to required tier
func hasTierAccess(userTier, requiredTier UserTier) bool {
	tierHierarchy := map[UserTier]int{
		TierFree:       1,
		TierPro:        2,
		TierEnterprise: 3,
	}

	return tierHierarchy[userTier] >= tierHierarchy[requiredTier]
}

// ============================================================================
// Context Helpers
// ============================================================================

// GetUserFromContext retrieves the User from context
func GetUserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(ContextKeyUser).(*User); ok {
		return user
	}
	return nil
}

// GetUserIDFromContext retrieves the user ID from context
func GetUserIDFromContext(ctx context.Context) string {
	if user := GetUserFromContext(ctx); user != nil {
		return user.ID.String()
	}
	return ""
}

// GetClerkUserIDFromContext retrieves the Clerk user ID from context
func GetClerkUserIDFromContext(ctx context.Context) string {
	if claims := ExtractClaimsFromContext(ctx); claims != nil {
		return claims.Subject
	}
	return ""
}

// GetSessionIDFromContext retrieves the session ID from context
func GetSessionIDFromContext(ctx context.Context) string {
	if sessionID, ok := ctx.Value(ContextKeySessionID).(string); ok {
		return sessionID
	}
	return ""
}

// IsAuthenticated checks if the request is authenticated
func IsAuthenticated(ctx context.Context) bool {
	return GetUserFromContext(ctx) != nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// convertClerkUser converts a Clerk SDK user to our User type
func convertClerkUser(clerkUser *clerk.User) *User {
	user := &User{
		ID:          uuid.New(), // This should be looked up from database
		ClerkUserID: clerkUser.ID,
		Tier:        TierFree, // Default tier, should be fetched from database
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Extract email from primary email address
	if clerkUser.PrimaryEmailAddressID != nil {
		for _, email := range clerkUser.EmailAddresses {
			if email.ID == *clerkUser.PrimaryEmailAddressID {
				user.Email = email.EmailAddress
				break
			}
		}
	}

	// Extract tier from public metadata if available
	if clerkUser.PublicMetadata != nil {
		var metadata map[string]interface{}
		if err := json.Unmarshal(clerkUser.PublicMetadata, &metadata); err == nil {
			if tier, ok := metadata["tier"].(string); ok {
				user.Tier = UserTier(tier)
			}
		}
	}

	return user
}

// GetRequestStartTime returns the request start time from context
func GetRequestStartTime(ctx context.Context) time.Time {
	if t, ok := ctx.Value("request_start_time").(time.Time); ok {
		return t
	}
	return time.Now()
}

// SetRequestStartTime sets the request start time in context
func SetRequestStartTime(ctx context.Context) context.Context {
	return context.WithValue(ctx, "request_start_time", time.Now())
}

// ============================================================================
// CORS Middleware
// ============================================================================

// CORSOptions contains CORS configuration
type CORSOptions struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCORSOptions returns default CORS options
func DefaultCORSOptions() CORSOptions {
	return CORSOptions{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key", "X-Request-ID"},
		ExposedHeaders:   []string{"Link", "X-Total-Count"},
		AllowCredentials: true,
		MaxAge:           300,
	}
}

// CORS middleware handles CORS headers
func CORS(opts CORSOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range opts.AllowedOrigins {
				if allowedOrigin == "*" || strings.EqualFold(allowedOrigin, origin) {
					allowed = true
					break
				}
			}

			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			if opts.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if len(opts.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(opts.ExposedHeaders, ", "))
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(opts.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(opts.AllowedHeaders, ", "))
				if opts.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", string(rune(opts.MaxAge)))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
