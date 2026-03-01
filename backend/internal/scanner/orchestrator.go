package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"

	"github.com/redteam/agentic-scanner/internal/classifier"
	"github.com/redteam/agentic-scanner/internal/compliance"
	"github.com/redteam/agentic-scanner/internal/modules"
	"github.com/redteam/agentic-scanner/internal/queue"
	"github.com/redteam/agentic-scanner/internal/store"
)

// ScanState holds the state of a running scan
type ScanState struct {
	ScanID           uuid.UUID
	Status           ScanStatus
	Progress         int
	CurrentModule    string
	ModulesCompleted []string
	ModulesPending   []string
	FindingsCount    int
	CancelFunc       context.CancelFunc
	StartedAt        time.Time
	mu               sync.RWMutex
}

// SetProgress updates the scan progress thread-safely
func (s *ScanState) SetProgress(percent int, module string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Progress = percent
	if module != "" {
		s.CurrentModule = module
	}
}

// AddCompletedModule marks a module as completed
func (s *ScanState) AddCompletedModule(module string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ModulesCompleted = append(s.ModulesCompleted, module)
	// Remove from pending
	for i, m := range s.ModulesPending {
		if m == module {
			s.ModulesPending = append(s.ModulesPending[:i], s.ModulesPending[i+1:]...)
			break
		}
	}
}

// IncrementFindings increments the findings count
func (s *ScanState) IncrementFindings() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FindingsCount++
}

// ToProgress returns the current progress as ScanProgress
func (s *ScanState) ToProgress() *ScanProgress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	eta := time.Now().Add(time.Duration(100-s.Progress) * 30 * time.Second)
	return &ScanProgress{
		ScanID:           s.ScanID,
		Status:           s.Status,
		ProgressPercent:  s.Progress,
		CurrentModule:    s.CurrentModule,
		ModulesCompleted: s.ModulesCompleted,
		ModulesPending:   s.ModulesPending,
		FindingsCount:    s.FindingsCount,
		ETA:              &eta,
		StartedAt:        &s.StartedAt,
		Timestamp:        time.Now(),
	}
}

// Orchestrator manages scan execution
type Orchestrator struct {
	db          *store.DB
	queue       *queue.Client
	registry    *ModuleRegistry
	classifier  *classifier.TargetClassifier
	auditLogger *compliance.AuditLogger
	scanStates  map[uuid.UUID]*ScanState
	statesMu    sync.RWMutex
	sseHub      SSEHub
}

// ScanClassification stores target classification for a scan
type ScanClassification struct {
	ScanID         uuid.UUID
	Classification *classifier.ClassificationResult
	Timestamp      time.Time
}

// SSEHub interface for publishing events
type SSEHub interface {
	Publish(event []byte)
}

// NewOrchestrator creates a new scan orchestrator
func NewOrchestrator(db *store.DB, queueClient *queue.Client) *Orchestrator {
	// Create registry and register modules
	reg := NewModuleRegistry()
	reg.Register(&modules.ReconModule{})
	reg.Register(&modules.WebModule{})
	reg.Register(&modules.APIModule{})
	reg.Register(&modules.AgenticModule{})
	reg.Register(&modules.IntelModule{})

	return &Orchestrator{
		db:          db,
		queue:       queueClient,
		registry:    reg,
		auditLogger: compliance.NewAuditLoggerSimple(),
		scanStates:  make(map[uuid.UUID]*ScanState),
	}
}

// SetClassifier sets the target classifier
func (o *Orchestrator) SetClassifier(c *classifier.TargetClassifier) {
	o.classifier = c
}

// SetSSEHub sets the SSE hub for publishing events
func (o *Orchestrator) SetSSEHub(hub SSEHub) {
	o.sseHub = hub
}

// EnqueueScan enqueues a scan task to Asynq
func (o *Orchestrator) EnqueueScan(ctx context.Context, scanID uuid.UUID, config ScanConfig) error {
	// Create scan state
	state := &ScanState{
		ScanID:         scanID,
		Status:         ScanStatusQueued,
		ModulesPending: config.Modules,
	}
	o.statesMu.Lock()
	o.scanStates[scanID] = state
	o.statesMu.Unlock()

	// Convert scanner.ScanConfig to queue.ScanConfig
	queueConfig := queue.ScanConfig{
		UserID:        config.UserID,
		Target:        config.Target,
		TargetType:    string(config.TargetType),
		Scope:         config.Scope,
		Modules:       config.Modules,
		Depth:         config.Depth,
		AISeverity:    config.AISeverity,
		MaxDuration:   int(config.MaxDuration.Seconds()),
		AuthConfirmed: config.AuthConfirmed,
		CustomHeaders: config.CustomHeaders,
	}

	// Enqueue the task with retry options
	_, err := o.queue.EnqueueScanTask(scanID, queueConfig,
		asynq.Queue(queue.QueueScan),
		asynq.MaxRetry(3),
		asynq.Timeout(config.MaxDuration),
	)

	return err
}

// ExecuteScan implements the queue.ScanExecutor interface
func (o *Orchestrator) ExecuteScan(ctx context.Context, scanID uuid.UUID) error {
	// Get scan details from database
	scanJob, err := o.db.GetScanJobByID(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	// Create cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Update scan state
	o.statesMu.Lock()
	if state, exists := o.scanStates[scanID]; exists {
		state.Status = ScanStatusRunning
		state.StartedAt = time.Now()
		state.CancelFunc = cancel
	} else {
		o.scanStates[scanID] = &ScanState{
			ScanID:     scanID,
			Status:     ScanStatusRunning,
			StartedAt:  time.Now(),
			CancelFunc: cancel,
		}
	}
	state := o.scanStates[scanID]
	o.statesMu.Unlock()

	// Update status to running in database
	if _, err := o.db.UpdateScanJobStarted(ctx, scanID); err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	// Publish scan started event
	o.publishEvent(ScanEvent{
		Type:      EventScanStarted,
		ScanID:    scanID,
		Timestamp: time.Now(),
		Data:      mustMarshal(ScanStartedData{Target: scanJob.Target}),
	})

	// Parse custom headers
	var customHeaders map[string]string
	if scanJob.CustomHeaders != nil {
		json.Unmarshal(scanJob.CustomHeaders, &customHeaders)
	}

	// Classify target if classifier is available
	var classification *classifier.ClassificationResult
	if o.classifier != nil {
		classifyCtx, classifyCancel := context.WithTimeout(scanCtx, 30*time.Second)
		classification, err = o.classifier.Classify(classifyCtx, scanJob.Target)
		classifyCancel()

		if err != nil {
			o.publishEvent(ScanEvent{
				Type:      EventWarning,
				ScanID:    scanID,
				Timestamp: time.Now(),
				Data:      mustMarshal(map[string]string{"warning": fmt.Sprintf("Classification failed: %v", err)}),
			})
		} else {
			// Publish classification event
			o.publishEvent(ScanEvent{
				Type:      EventTargetClassified,
				ScanID:    scanID,
				Timestamp: time.Now(),
				Data:      mustMarshal(classification),
			})

			// Log classification details
			classJSON, _ := classification.ToJSON()
			fmt.Printf("Target classification: %s\n", string(classJSON))
		}
	}

	// Determine modules to run based on classification or scope
	moduleList := o.determineModules(scanJob.Scope, classification)

	// Add warnings from classification
	if classification != nil {
		for _, warning := range classification.Warnings {
			o.publishEvent(ScanEvent{
				Type:      EventWarning,
				ScanID:    scanID,
				Timestamp: time.Now(),
				Data:      mustMarshal(map[string]string{"warning": warning}),
			})
		}
	}

	totalModules := len(moduleList)
	findings := []modules.Finding{}

	for i, moduleName := range moduleList {
		select {
		case <-scanCtx.Done():
			// Scan was cancelled
			o.handleCancellation(ctx, scanID, state)
			return nil
		default:
		}

		// Update progress
		progress := (i * 100) / totalModules
		state.SetProgress(progress, moduleName)

		// Publish module started event
		o.publishEvent(ScanEvent{
			Type:      EventModuleStarted,
			ScanID:    scanID,
			Timestamp: time.Now(),
			Data:      mustMarshal(ModuleStartedData{Module: moduleName}),
		})

		// Execute module
		moduleResult := o.executeModule(scanCtx, moduleName, modules.ModuleConfig{
			Target:      scanJob.Target,
			Depth:       1,
			AISeverity:  "",
			MaxDuration: 30 * time.Minute,
		})

		// Handle module result
		state.AddCompletedModule(moduleName)
		for _, finding := range moduleResult.Findings {
			state.IncrementFindings()
			findings = append(findings, finding)

			// Publish finding event - convert to scanner.Finding for event
			scannerFinding := convertToScannerFinding(finding, scanID)
			o.publishEvent(ScanEvent{
				Type:      EventFindingDiscovered,
				ScanID:    scanID,
				Timestamp: time.Now(),
				Data:      mustMarshal(FindingEventData{Finding: scannerFinding}),
			})
		}

		// Publish module completed event
		o.publishEvent(ScanEvent{
			Type:      EventModuleCompleted,
			ScanID:    scanID,
			Timestamp: time.Now(),
			Data: mustMarshal(ModuleCompletedData{
				Module:   moduleName,
				Findings: len(moduleResult.Findings),
			}),
		})
	}

	// Mark as completed
	state.SetProgress(100, "")
	state.Status = ScanStatusCompleted

	// Calculate summary (convert findings for summary)
	summary := o.calculateSummaryFromModules(findings)
	findingCountsJSON, _ := json.Marshal(summary)

	// Update scan as completed
	riskScore := int32(summary.RiskScore * 10)
	if _, err := o.db.UpdateScanJobCompleted(ctx, store.UpdateScanJobCompletedParams{
		ID:            scanID,
		RiskScore:     riskScore,
		FindingCounts: findingCountsJSON,
	}); err != nil {
		return fmt.Errorf("failed to update scan completion: %w", err)
	}

	// Publish completion event
	o.publishEvent(ScanEvent{
		Type:      EventScanCompleted,
		ScanID:    scanID,
		Timestamp: time.Now(),
		Data:      mustMarshal(summary),
	})

	return nil
}

// executeModule executes a single module
func (o *Orchestrator) executeModule(ctx context.Context, name string, config modules.ModuleConfig) modules.ModuleResult {
	result := modules.ModuleResult{
		Module:    name,
		Status:    "completed",
		Findings:  []modules.Finding{},
		StartedAt: time.Now(),
	}

	// Get module from registry
	module, err := o.registry.Get(name)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}

	// Execute with timeout
	moduleCtx, cancel := context.WithTimeout(ctx, config.MaxDuration)
	defer cancel()

	// Run module
	moduleResult := module.Execute(moduleCtx, config)
	result.Findings = moduleResult.Findings

	now := time.Now()
	result.EndedAt = &now

	return result
}

// handleCancellation handles scan cancellation cleanup
func (o *Orchestrator) handleCancellation(ctx context.Context, scanID uuid.UUID, state *ScanState) {
	state.Status = ScanStatusCancelled
	o.db.UpdateScanJobStatus(ctx, store.UpdateScanJobStatusParams{
		ID:     scanID,
		Status: string(ScanStatusCancelled),
	})

	o.publishEvent(ScanEvent{
		Type:      EventScanCancelled,
		ScanID:    scanID,
		Timestamp: time.Now(),
		Data:      mustMarshal(map[string]string{"reason": "user_cancelled"}),
	})
}

// CancelScan cancels a running scan
func (o *Orchestrator) CancelScan(scanID uuid.UUID) error {
	o.statesMu.Lock()
	defer o.statesMu.Unlock()

	state, exists := o.scanStates[scanID]
	if !exists {
		return fmt.Errorf("scan not found or not running")
	}

	if state.Status.IsTerminal() {
		return fmt.Errorf("scan is already in terminal state: %s", state.Status)
	}

	if state.CancelFunc != nil {
		state.CancelFunc()
	}

	state.Status = ScanStatusCancelled
	return nil
}

// GetScanProgress returns the current progress for a scan
func (o *Orchestrator) GetScanProgress(scanID uuid.UUID) *ScanProgress {
	o.statesMu.RLock()
	defer o.statesMu.RUnlock()

	state, exists := o.scanStates[scanID]
	if !exists {
		return nil
	}

	return state.ToProgress()
}

// determineModules determines which modules to run based on scope and classification
func (o *Orchestrator) determineModules(scope string, classification *classifier.ClassificationResult) []string {
	// If we have classification results, use them to determine modules
	if classification != nil && len(classification.SuggestedModules) > 0 {
		// Filter based on scope
		switch scope {
		case "quick":
			// Quick scan: only recon
			return []string{"recon"}
		case "comprehensive":
			// Comprehensive: use all suggested modules
			return ensureModuleInList(classification.SuggestedModules, "intel")
		default:
			// Standard: use suggested modules but ensure intel is included
			return ensureModuleInList(classification.SuggestedModules, "intel")
		}
	}

	// Fallback to scope-based selection
	switch scope {
	case "quick":
		return []string{"recon"}
	case "comprehensive":
		return []string{"recon", "web", "api", "agentic", "intel"}
	default:
		return []string{"recon", "web", "api", "intel"}
	}
}

// ensureModuleInList ensures a module is in the list (avoiding duplicates)
func ensureModuleInList(modules []string, required string) []string {
	for _, m := range modules {
		if m == required {
			return modules
		}
	}
	return append(modules, required)
}

// calculateSummary calculates findings summary
func (o *Orchestrator) calculateSummary(findings []Finding) ScanSummary {
	summary := ScanSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
	}

	for _, f := range findings {
		summary.BySeverity[string(f.Severity)]++
		summary.ByCategory[f.Category]++
	}

	// Calculate risk score (0-10)
	score := float64(summary.BySeverity["critical"]*10 +
		summary.BySeverity["high"]*5 +
		summary.BySeverity["medium"]*2 +
		summary.BySeverity["low"])
	if score > 100 {
		score = 100
	}
	summary.RiskScore = score / 10

	return summary
}

// publishEvent publishes an event to SSE hub
func (o *Orchestrator) publishEvent(event ScanEvent) {
	if o.sseHub == nil {
		return
	}

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	o.sseHub.Publish(data)
}

// GetAvailableModules returns list of available scanning modules
func (o *Orchestrator) GetAvailableModules() []modules.ModuleInfo {
	return o.registry.ListModules()
}

// Helper function to marshal data
func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// Legacy methods for backward compatibility

// CreateScan creates and queues a new scan (legacy)
func (o *Orchestrator) CreateScan(ctx context.Context, config ScanConfig) (*Scan, error) {
	scan := &Scan{
		ID:          uuid.New(),
		UserID:      config.UserID,
		Target:      config.Target,
		Status:      string(ScanStatusPending),
		Modules:     config.Modules,
		Depth:       config.Depth,
		AISeverity:  config.AISeverity,
		MaxDuration: int(config.MaxDuration.Seconds()),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	return scan, nil
}

// GetScan retrieves a scan by ID (legacy)
func (o *Orchestrator) GetScan(ctx context.Context, id uuid.UUID) (*Scan, error) {
	// This is a stub - in production would fetch from DB
	return &Scan{ID: id}, nil
}

// ListScans retrieves scans for a user (legacy)
func (o *Orchestrator) ListScans(ctx context.Context, userID string) ([]*Scan, error) {
	return []*Scan{}, nil
}

// StopScan stops a running scan (legacy)
func (o *Orchestrator) StopScan(ctx context.Context, id uuid.UUID) error {
	return o.CancelScan(id)
}

// GetReport retrieves the report for a scan (legacy)
func (o *Orchestrator) GetReport(ctx context.Context, scanID uuid.UUID) (*Report, error) {
	return &Report{ID: uuid.New(), ScanID: scanID}, nil
}

// convertToScannerFinding converts modules.Finding to scanner.Finding
func convertToScannerFinding(f modules.Finding, scanID uuid.UUID) Finding {
	return Finding{
		ID:          f.ID,
		ScanID:      scanID,
		Module:      f.Module,
		Title:       f.Title,
		Description: f.Description,
		Severity:    Severity(f.Severity),
		Category:    f.Category,
		Evidence: FindingEvidence{
			Request:    f.Evidence.Request,
			Response:   f.Evidence.Response,
			Headers:    f.Evidence.Headers,
			Payload:    f.Evidence.Payload,
			Snippet:    f.Evidence.Snippet,
			URL:        f.Evidence.URL,
			Screenshot: f.Evidence.Screenshot,
		},
		Remediation: f.Remediation,
		CVSS:        f.CVSS,
		CVEs:        f.CVEs,
		References:  f.References,
		CreatedAt:   f.CreatedAt,
	}
}

// calculateSummaryFromModules calculates summary from module findings
func (o *Orchestrator) calculateSummaryFromModules(findings []modules.Finding) ScanSummary {
	summary := ScanSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
	}

	for _, f := range findings {
		summary.BySeverity[string(f.Severity)]++
		summary.ByCategory[f.Category]++
	}

	// Calculate risk score (0-10)
	score := float64(summary.BySeverity["critical"]*10 +
		summary.BySeverity["high"]*5 +
		summary.BySeverity["medium"]*2 +
		summary.BySeverity["low"])
	if score > 100 {
		score = 100
	}
	summary.RiskScore = score / 10

	return summary
}
