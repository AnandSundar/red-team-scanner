package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

// TaskProcessor handles task processing
type TaskProcessor struct {
	scanExecutor ScanExecutor
	mux          *asynq.ServeMux
}

// ScanExecutor defines the interface for scan execution
// This avoids import cycle between queue and scanner packages
type ScanExecutor interface {
	ExecuteScan(ctx context.Context, scanID uuid.UUID) error
	CancelScan(scanID uuid.UUID) error
}

// NewTaskProcessor creates a new task processor
func NewTaskProcessor(executor ScanExecutor) *TaskProcessor {
	p := &TaskProcessor{
		scanExecutor: executor,
		mux:          asynq.NewServeMux(),
	}

	p.mux.HandleFunc(TypeScan, p.handleScanTask)
	p.mux.HandleFunc(TypeReport, p.handleReportTask)
	p.mux.HandleFunc(TypeClassify, p.handleClassificationTask)

	return p
}

// Run starts the task processor
func (p *TaskProcessor) Run(redisOpt asynq.RedisConnOpt) error {
	srv := asynq.NewServer(
		redisOpt,
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				QueueDefault: 1,
				QueueScan:    5,
				QueueReport:  2,
			},
			RetryDelayFunc: func(n int, e error, t *asynq.Task) time.Duration {
				// Exponential backoff: 10s, 30s, 90s...
				return time.Duration(10*(3^(n-1))) * time.Second
			},
		},
	)

	return srv.Run(p.mux)
}

// ScanTaskPayload represents the payload for a scan task
type ScanTaskPayload struct {
	ScanID uuid.UUID  `json:"scan_id"`
	Config ScanConfig `json:"config"`
}

// ScanConfig represents scan configuration in queue payload
type ScanConfig struct {
	UserID        string            `json:"user_id"`
	Target        string            `json:"target"`
	TargetType    string            `json:"target_type"`
	Scope         string            `json:"scope"`
	Modules       []string          `json:"modules"`
	Depth         int               `json:"depth"`
	AISeverity    string            `json:"ai_severity"`
	MaxDuration   int               `json:"max_duration_seconds"`
	AuthConfirmed bool              `json:"auth_confirmed"`
	CustomHeaders map[string]string `json:"custom_headers"`
}

// ReportTaskPayload represents the payload for a report task
type ReportTaskPayload struct {
	ScanID uuid.UUID `json:"scan_id"`
}

// ClassificationTaskPayload represents the payload for a classification task
type ClassificationTaskPayload struct {
	FindingID uuid.UUID `json:"finding_id"`
	Context   string    `json:"context"`
}

func (p *TaskProcessor) handleScanTask(ctx context.Context, t *asynq.Task) error {
	var payload ScanTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal scan task: %w", err)
	}

	log.Printf("Processing scan task: %s", payload.ScanID)

	// Execute scan with timeout
	if payload.Config.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(payload.Config.MaxDuration)*time.Second)
		defer cancel()
	}

	if err := p.scanExecutor.ExecuteScan(ctx, payload.ScanID); err != nil {
		log.Printf("Scan execution failed: %v", err)
		return fmt.Errorf("failed to execute scan: %w", err)
	}

	return nil
}

func (p *TaskProcessor) handleReportTask(ctx context.Context, t *asynq.Task) error {
	var payload ReportTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal report task: %w", err)
	}

	log.Printf("Processing report task: %s", payload.ScanID)

	// Report generation is handled within the scan orchestrator
	// This task is for async report regeneration if needed

	return nil
}

func (p *TaskProcessor) handleClassificationTask(ctx context.Context, t *asynq.Task) error {
	var payload ClassificationTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal classification task: %w", err)
	}

	log.Printf("Processing classification task: %s", payload.FindingID)

	// TODO: Implement AI-based classification

	return nil
}

// NewScanTask creates a new scan task payload for Asynq
func NewScanTaskPayload(scanID uuid.UUID, config ScanConfig) ([]byte, error) {
	payload := ScanTaskPayload{
		ScanID: scanID,
		Config: config,
	}
	return json.Marshal(payload)
}

// NewReportTaskPayload creates a new report task payload
func NewReportTaskPayload(scanID uuid.UUID) ([]byte, error) {
	payload := ReportTaskPayload{
		ScanID: scanID,
	}
	return json.Marshal(payload)
}

// NewClassificationTaskPayload creates a new classification task payload
func NewClassificationTaskPayload(findingID uuid.UUID, context string) ([]byte, error) {
	payload := ClassificationTaskPayload{
		FindingID: findingID,
		Context:   context,
	}
	return json.Marshal(payload)
}
