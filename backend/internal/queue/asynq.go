package queue

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

const (
	QueueDefault = "default"
	QueueScan    = "scan"
	QueueReport  = "report"
)

// Task types
const (
	TypeScan     = "scan:execute"
	TypeReport   = "report:generate"
	TypeClassify = "classify:finding"
)

// Client wraps the Asynq client
type Client struct {
	client *asynq.Client
}

// NewClient creates a new queue client
func NewClient(redisOpt asynq.RedisConnOpt) *Client {
	return &Client{
		client: asynq.NewClient(redisOpt),
	}
}

// Enqueue adds a task to the queue
func (c *Client) Enqueue(task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	return c.client.Enqueue(task, opts...)
}

// Close closes the client connection
func (c *Client) Close() error {
	return c.client.Close()
}

// EnqueueScanTask creates and enqueues a new scan task
func (c *Client) EnqueueScanTask(scanID uuid.UUID, config ScanConfig, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	payload, err := NewScanTaskPayload(scanID, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan task payload: %w", err)
	}

	task := asynq.NewTask(TypeScan, payload)
	return c.client.Enqueue(task, opts...)
}

// EnqueueReportTask creates and enqueues a new report generation task
func (c *Client) EnqueueReportTask(scanID uuid.UUID, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	payload, err := NewReportTaskPayload(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to create report task payload: %w", err)
	}

	task := asynq.NewTask(TypeReport, payload)
	return c.client.Enqueue(task, opts...)
}

// EnqueueClassificationTask creates and enqueues a new classification task
func (c *Client) EnqueueClassificationTask(findingID uuid.UUID, context string, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	payload, err := NewClassificationTaskPayload(findingID, context)
	if err != nil {
		return nil, fmt.Errorf("failed to create classification task payload: %w", err)
	}

	task := asynq.NewTask(TypeClassify, payload)
	return c.client.Enqueue(task, opts...)
}
