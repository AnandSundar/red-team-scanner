package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/billing"
	"github.com/redteam/agentic-scanner/internal/store"
)

// ============================================================================
// Request Logging Middleware
// ============================================================================

// StructuredLogger is a middleware that logs requests in a structured format
func StructuredLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Get request ID
		requestID := middleware.GetReqID(r.Context())

		// Process request
		next.ServeHTTP(ww, r.WithContext(context.WithValue(r.Context(), "request_start_time", start)))

		// Get user ID if authenticated
		userID := "anonymous"
		if user := auth.GetUserFromContext(r.Context()); user != nil {
			userID = user.ID.String()
		}

		// Log request details
		duration := time.Since(start)
		status := ww.Status()
		bytesWritten := ww.BytesWritten()

		// Build log entry (in production, use structured logging)
		logEntry := map[string]interface{}{
			"timestamp":     start.Format(time.RFC3339),
			"request_id":    requestID,
			"user_id":       userID,
			"method":        r.Method,
			"path":          r.URL.Path,
			"status":        status,
			"duration_ms":   duration.Milliseconds(),
			"bytes_written": bytesWritten,
			"user_agent":    r.UserAgent(),
			"ip":            r.RemoteAddr,
		}

		// In production, use proper JSON logging
		_ = logEntry
	})
}

// ============================================================================
// Rate Limiting Middleware
// ============================================================================

// RateLimiter implements rate limiting per user tier
type RateLimiter struct {
	store RateLimitStore
}

// RateLimitStore interface for rate limit data storage
type RateLimitStore interface {
	GetRequests(ctx context.Context, key string, window time.Duration) (int, error)
	IncrementRequests(ctx context.Context, key string, window time.Duration) error
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(store RateLimitStore) *RateLimiter {
	return &RateLimiter{store: store}
}

// RateLimit middleware implements tier-based rate limiting
func (rl *RateLimiter) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			// No user, use IP-based rate limiting
			ipKey := "ip:" + getClientIP(r)
			if !rl.checkLimit(r.Context(), ipKey, auth.RateLimit{
				RequestsPerMinute: 30,
				RequestsPerHour:   100,
				RequestsPerDay:    500,
			}) {
				auth.WriteAuthError(w, auth.ErrRateLimitExceeded)
				return
			}
		} else {
			// User-based rate limiting
			userKey := "user:" + user.ID.String()
			if !rl.checkLimit(r.Context(), userKey, user.GetRateLimit()) {
				auth.WriteAuthError(w, auth.ErrRateLimitExceeded)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// checkLimit checks if the request is within rate limits
func (rl *RateLimiter) checkLimit(ctx context.Context, key string, limit auth.RateLimit) bool {
	// Per-minute check
	if rl.store != nil {
		count, err := rl.store.GetRequests(ctx, key+":minute", time.Minute)
		if err != nil || count >= limit.RequestsPerMinute {
			return false
		}
		rl.store.IncrementRequests(ctx, key+":minute", time.Minute)

		// Per-hour check
		count, err = rl.store.GetRequests(ctx, key+":hour", time.Hour)
		if err != nil || count >= limit.RequestsPerHour {
			return false
		}
		rl.store.IncrementRequests(ctx, key+":hour", time.Hour)

		// Per-day check
		count, err = rl.store.GetRequests(ctx, key+":day", 24*time.Hour)
		if err != nil || count >= limit.RequestsPerDay {
			return false
		}
		rl.store.IncrementRequests(ctx, key+":day", 24*time.Hour)
	}

	return true
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// ============================================================================
// CORS Middleware
// ============================================================================

// CORSConfig contains CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCORSConfig returns default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3000", "https://app.redteamscanner.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key", "X-Request-ID", "X-Clerk-Auth"},
		ExposedHeaders:   []string{"Link", "X-Total-Count", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	}
}

// CORSMiddleware handles CORS headers
func CORSMiddleware(config CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range config.AllowedOrigins {
				if allowedOrigin == "*" || strings.EqualFold(allowedOrigin, origin) {
					allowed = true
					break
				}
			}

			if allowed {
				if len(config.AllowedOrigins) == 1 && config.AllowedOrigins[0] == "*" {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				}
			}

			if config.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if len(config.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
				if config.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// Security Headers Middleware
// ============================================================================

// SecurityHeaders adds security headers to responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// RLS Context Middleware
// ============================================================================

// SetRLSContext sets the Row Level Security context for database queries
func SetRLSContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user != nil {
			// Set user ID in context for RLS
			ctx := context.WithValue(r.Context(), "rls_user_id", user.ID)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// GetRLSUserID retrieves the RLS user ID from context
func GetRLSUserID(ctx context.Context) uuid.UUID {
	if userID, ok := ctx.Value("rls_user_id").(uuid.UUID); ok {
		return userID
	}
	return uuid.Nil
}

// ============================================================================
// Request ID Middleware
// ============================================================================

// RequestID adds a request ID to the context and response headers
func RequestID(next http.Handler) http.Handler {
	return middleware.RequestID(next)
}

// ============================================================================
// Recovery Middleware
// ============================================================================

// Recoverer handles panics gracefully
func Recoverer(next http.Handler) http.Handler {
	return middleware.Recoverer(next)
}

// ============================================================================
// Timeout Middleware
// ============================================================================

// Timeout sets a timeout for request processing
func Timeout(duration time.Duration) func(http.Handler) http.Handler {
	return middleware.Timeout(duration)
}

// ============================================================================
// Phase 16: Tier Enforcement Middleware
// ============================================================================

// RequireTier enforces a minimum tier requirement
func RequireTier(minTier auth.UserTier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				respondError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Check if user's tier meets the minimum requirement
			if !isTierAtLeast(user.Tier, minTier) {
				respondError(w, http.StatusForbidden, fmt.Sprintf("This feature requires %s tier or higher", minTier))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isTierAtLeast checks if userTier is at least minTier
func isTierAtLeast(userTier, minTier auth.UserTier) bool {
	tierHierarchy := map[auth.UserTier]int{
		auth.TierFree:       0,
		auth.TierPro:        1,
		auth.TierTeam:       2,
		auth.TierEnterprise: 3,
	}

	userLevel := tierHierarchy[userTier]
	minLevel := tierHierarchy[minTier]

	return userLevel >= minLevel
}

// RequireScope checks if the user's tier allows the requested scan scope
func RequireScope(db *store.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only check on POST requests (scan creation)
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				respondError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Parse request to get scope
			var req struct {
				Scope string `json:"scope"`
			}

			// Try to parse body (we'll need to restore it for the next handler)
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()

			if len(body) > 0 {
				json.Unmarshal(body, &req)
				// Restore body for next handler
				r.Body = io.NopCloser(bytes.NewBuffer(body))
			}

			// Default to standard scope
			scope := req.Scope
			if scope == "" {
				scope = "standard"
			}

			// Check if scope is allowed for user's tier
			tier := billing.Tier(user.Tier)
			if !billing.CheckScopeAllowed(tier, scope) {
				respondError(w, http.StatusForbidden,
					fmt.Sprintf("The '%s' scan scope requires a higher tier. Please upgrade your subscription.", scope))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CheckScanLimit middleware enforces daily scan limits based on tier
func CheckScanLimit(db *store.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only check on POST requests (scan creation)
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				respondError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Check if user has exceeded their daily scan limit
			allowed, err := db.CheckScanLimit(r.Context(), user.ID, string(user.Tier))
			if err != nil {
				respondError(w, http.StatusInternalServerError, "Failed to check scan limit")
				return
			}

			if !allowed {
				respondError(w, http.StatusTooManyRequests,
					"Daily scan limit reached. Please upgrade your subscription for unlimited scans.")
				return
			}

			// Increment scan count
			_, err = db.IncrementDailyScanCount(r.Context(), user.ID)
			if err != nil {
				// Log but don't fail the request
				fmt.Printf("Failed to increment scan count: %v\n", err)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireFeature checks if the user has access to a specific feature
func RequireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				respondError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			tier := billing.Tier(user.Tier)
			if !billing.HasFeature(tier, feature) {
				respondError(w, http.StatusForbidden,
					fmt.Sprintf("The '%s' feature is not available on your current tier", feature))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
