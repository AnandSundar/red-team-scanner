package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/scanner"
	"github.com/redteam/agentic-scanner/internal/store"
)

// SetupRoutes configures all API routes with authentication groups
func SetupRoutes(r chi.Router, orchestrator *scanner.Orchestrator, db *store.DB, authMiddleware *auth.Middleware) {
	handler := NewHandler(orchestrator, db)
	billingHandler, _ := NewBillingHandler(db, nil)

	// ============================================================================
	// Public Routes (No Authentication Required)
	// ============================================================================
	r.Group(func(r chi.Router) {
		// Health check
		r.Get("/health", handler.HealthCheck)

		// Stripe webhooks (must be public for Stripe to call)
		r.Post("/webhooks/stripe", billingHandler.StripeWebhookHandler)

		// Clerk webhooks (must be public for Clerk to call)
		r.Post("/webhooks/clerk", handler.ClerkWebhook)

		// Public module information
		r.Get("/modules", handler.GetModules)

		// Public API documentation
		r.Get("/docs", handler.GetAPIDocs)

		// Public shared report access (no auth required)
		r.Get("/share/{token}", handler.GetSharedReport)
	})

	// ============================================================================
	// Authenticated Routes (Session Token or Cookie)
	// ============================================================================
	r.Group(func(r chi.Router) {
		// Apply authentication middleware
		r.Use(authMiddleware.RequireAuth())

		// Scan management routes
		r.Route("/scans", func(r chi.Router) {
			// Apply tier-based limits to scan creation
			r.With(CheckScanLimit(db), RequireScope(db)).
				Post("/", handler.CreateScan) // Create new scan
			r.Get("/", handler.ListScans)             // List user's scans
			r.Get("/history", handler.GetScanHistory) // Get scan history
			r.Get("/search", handler.SearchScans)     // Search scans

			r.Route("/{scanID}", func(r chi.Router) {
				r.Get("/", handler.GetScan)                  // Get scan details
				r.Delete("/", handler.DeleteScan)            // Delete scan
				r.Post("/stop", handler.StopScan)            // Stop running scan
				r.Post("/retry", handler.RetryScan)          // Retry failed scan
				r.Get("/status", handler.GetScanStatus)      // Get scan status
				r.Get("/report", handler.GetScanReport)      // Get scan report
				r.Get("/findings", handler.GetScanFindings)  // Get scan findings
				r.Post("/auth-confirm", handler.ConfirmAuth) // Confirm authorization
			})
		})

		// Report routes
		r.Route("/reports", func(r chi.Router) {
			r.Get("/", handler.ListReports)                       // List user's reports
			r.Get("/{reportID}", handler.GetReport)               // Get report details
			r.Get("/{reportID}/download", handler.DownloadReport) // Download report
			r.Post("/{reportID}/share", handler.ShareReport)      // Share report
			r.Delete("/{reportID}/share", handler.RevokeShare)    // Revoke share
		})

		// Scan report routes
		r.Route("/scans/{scanID}", func(r chi.Router) {
			r.Get("/report", handler.GetScanReport)            // Get scan report
			r.Post("/report/generate", handler.GenerateReport) // Generate report
			r.Post("/rerun", handler.RerunScanHandler)         // Rerun scan with same config
		})

		// Diff routes
		r.Route("/scans/{scanID1}/diff/{scanID2}", func(r chi.Router) {
			r.Get("/", handler.DiffScansHandler) // Compare two scans
		})

		// Dashboard routes (Phase 15)
		r.Route("/dashboard", func(r chi.Router) {
			r.Get("/stats", handler.DashboardStatsHandler)       // Get dashboard statistics
			r.Get("/activity", handler.DashboardActivityHandler) // Get recent scan activity
			r.Get("/trends", handler.DashboardTrendsHandler)     // Get vulnerability trends
			r.Get("/targets", handler.DashboardTargetsHandler)   // Get most scanned targets
		})

		// History routes (Phase 15)
		r.Route("/history", func(r chi.Router) {
			r.Get("/", handler.ListHistoryHandler)              // List all scans with filtering
			r.Get("/{target}", handler.GetTargetHistoryHandler) // Scan history for specific target
		})

		// Billing routes (Phase 16)
		r.Route("/billing", func(r chi.Router) {
			r.Get("/subscription", billingHandler.GetSubscriptionHandler) // Get current subscription
			r.Post("/checkout", billingHandler.CreateCheckoutHandler)     // Create Stripe Checkout
			r.Get("/portal", billingHandler.CustomerPortalHandler)        // Get Customer Portal URL
		})

		// Compliance routes (Phase 17)
		complianceHandler := NewComplianceHandler(db)
		r.Route("/compliance", func(r chi.Router) {
			// Terms of Service
			r.Get("/tos", complianceHandler.GetToSStatusHandler)          // Get ToS acceptance status
			r.Post("/tos", complianceHandler.AcceptToSHandler)            // Accept ToS
			r.Get("/tos/content", complianceHandler.GetToSContentHandler) // Get ToS content

			// Privacy / GDPR / CCPA
			r.Get("/data-export", complianceHandler.ExportDataHandler)             // Export user data
			r.Post("/data-deletion", complianceHandler.RequestDataDeletionHandler) // Request data deletion
			r.Get("/privacy-policy", complianceHandler.GetPrivacyPolicyHandler)    // Get privacy policy

			// Consent management
			r.Post("/consent", complianceHandler.RecordConsentHandler)          // Record consent
			r.Get("/consent/{type}", complianceHandler.GetConsentStatusHandler) // Get consent status

			// Audit logs
			r.Get("/audit-logs", complianceHandler.GetAuditLogsHandler) // Get user audit logs

			// Blocklist info
			r.Get("/blocklist", complianceHandler.GetBlocklistInfoHandler) // Get blocked ranges
			r.Post("/check-target", complianceHandler.CheckTargetHandler)  // Check if target is allowed
		})

		// User settings and profile
		r.Route("/user", func(r chi.Router) {
			r.Get("/profile", handler.GetUserProfile)        // Get user profile
			r.Patch("/profile", handler.UpdateUserProfile)   // Update user profile
			r.Get("/settings", handler.GetUserSettings)      // Get user settings
			r.Patch("/settings", handler.UpdateUserSettings) // Update user settings
		})

		// API Key management (requires Pro tier or higher)
		r.Route("/apikeys", func(r chi.Router) {
			r.Use(authMiddleware.RequireTier(auth.TierPro))
			r.Post("/", handler.GenerateAPIKey)        // Generate new API key
			r.Get("/", handler.ListAPIKeys)            // List API keys
			r.Delete("/{keyID}", handler.RevokeAPIKey) // Revoke API key
		})
	})

	// ============================================================================
	// API Key Routes (For CI/CD Integration - API Key Authentication)
	// ============================================================================
	r.Route("/api/v1", func(r chi.Router) {
		// Apply API key authentication middleware
		r.Use(authMiddleware.RequireAPIKey())

		// CI/CD scan endpoints
		r.Route("/scans", func(r chi.Router) {
			r.Post("/", handler.CreateScan)                         // Create scan via API key
			r.Get("/", handler.ListScans)                           // List scans via API key
			r.Get("/{scanID}", handler.GetScan)                     // Get scan details
			r.Get("/{scanID}/status", handler.GetScanStatus)        // Get scan status
			r.Get("/{scanID}/report", handler.GetScanReport)        // Get scan report (JSON)
			r.Get("/{scanID}/report/pdf", handler.GetScanReportPDF) // Get scan report (PDF)
		})

		// Health check for API key users
		r.Get("/health", handler.HealthCheck)
	})

	// ============================================================================
	// Admin Routes (Requires Admin Role)
	// ============================================================================
	r.Route("/admin", func(r chi.Router) {
		r.Use(authMiddleware.RequireAuth())
		r.Use(authMiddleware.RequireAdmin())

		// User management
		r.Get("/users", handler.ListUsers)
		r.Get("/users/{userID}", handler.GetUser)
		r.Patch("/users/{userID}/tier", handler.UpdateUserTier)

		// System stats
		r.Get("/stats", handler.GetSystemStats)
		r.Get("/scans/all", handler.ListAllScans)
	})
}

// ============================================================================
// Handler Placeholder Methods
// These should be implemented in handlers.go
// ============================================================================

// HealthCheck returns the health status of the API
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// StripeWebhook handles Stripe webhook events
func (h *Handler) StripeWebhook(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Stripe webhook handler
	w.WriteHeader(http.StatusOK)
}

// ClerkWebhook handles Clerk webhook events
func (h *Handler) ClerkWebhook(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Clerk webhook handler
	w.WriteHeader(http.StatusOK)
}

// GetAPIDocs returns API documentation
func (h *Handler) GetAPIDocs(w http.ResponseWriter, r *http.Request) {
	// TODO: Return API documentation
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"docs":"API documentation"}`))
}

// SearchScans searches for scans
func (h *Handler) SearchScans(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement search
	w.WriteHeader(http.StatusOK)
}

// RetryScan retries a failed scan
func (h *Handler) RetryScan(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement retry
	w.WriteHeader(http.StatusOK)
}

// ConfirmAuth confirms authorization for a scan
func (h *Handler) ConfirmAuth(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement auth confirmation
	w.WriteHeader(http.StatusOK)
}

// GetDashboardStats gets dashboard statistics
func (h *Handler) GetDashboardStats(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement dashboard stats
	w.WriteHeader(http.StatusOK)
}

// GetScanTrends gets scan trends
func (h *Handler) GetScanTrends(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement trends
	w.WriteHeader(http.StatusOK)
}

// GetTopTargets gets top targets
func (h *Handler) GetTopTargets(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement top targets
	w.WriteHeader(http.StatusOK)
}

// GetUserProfile gets user profile
func (h *Handler) GetUserProfile(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement get profile
	w.WriteHeader(http.StatusOK)
}

// UpdateUserProfile updates user profile
func (h *Handler) UpdateUserProfile(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement update profile
	w.WriteHeader(http.StatusOK)
}

// GetUserSettings gets user settings
func (h *Handler) GetUserSettings(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement get settings
	w.WriteHeader(http.StatusOK)
}

// UpdateUserSettings updates user settings
func (h *Handler) UpdateUserSettings(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement update settings
	w.WriteHeader(http.StatusOK)
}

// GenerateAPIKey generates a new API key
func (h *Handler) GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement generate API key
	w.WriteHeader(http.StatusCreated)
}

// ListAPIKeys lists API keys
func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement list API keys
	w.WriteHeader(http.StatusOK)
}

// RevokeAPIKey revokes an API key
func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement revoke API key
	w.WriteHeader(http.StatusNoContent)
}

// GetScanReportPDF returns a PDF report
func (h *Handler) GetScanReportPDF(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement PDF report
	w.Header().Set("Content-Type", "application/pdf")
	w.WriteHeader(http.StatusOK)
}

// ListUsers lists all users (admin only)
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement list users
	w.WriteHeader(http.StatusOK)
}

// GetUser gets a user (admin only)
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement get user
	w.WriteHeader(http.StatusOK)
}

// UpdateUserTier updates a user's tier (admin only)
func (h *Handler) UpdateUserTier(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement update tier
	w.WriteHeader(http.StatusOK)
}

// GetSystemStats gets system stats (admin only)
func (h *Handler) GetSystemStats(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement system stats
	w.WriteHeader(http.StatusOK)
}

// ListAllScans lists all scans (admin only)
func (h *Handler) ListAllScans(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement list all scans
	w.WriteHeader(http.StatusOK)
}

// GetScanHistory gets scan history
func (h *Handler) GetScanHistory(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement scan history
	w.WriteHeader(http.StatusOK)
}

// DeleteScan deletes a scan
func (h *Handler) DeleteScan(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement delete scan
	w.WriteHeader(http.StatusNoContent)
}

// GetScanStatus gets scan status
func (h *Handler) GetScanStatus(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement get scan status
	w.WriteHeader(http.StatusOK)
}

// GetScanFindings gets scan findings
func (h *Handler) GetScanFindings(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement get scan findings
	w.WriteHeader(http.StatusOK)
}
