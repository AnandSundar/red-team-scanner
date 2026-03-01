package modules

import (
	"context"
	"time"
)

// Module defines the interface for scanning modules
// This is defined here to avoid import cycles
type Module interface {
	Name() string
	Description() string
	Execute(ctx context.Context, config ModuleConfig) ModuleResult
}

// ModuleConfig contains configuration for module execution
type ModuleConfig struct {
	Target      string
	Depth       int
	AISeverity  string
	MaxDuration time.Duration
}

// ModuleResult contains results from a single module
type ModuleResult struct {
	Module    string     `json:"module"`
	Status    string     `json:"status"`
	Findings  []Finding  `json:"findings"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// ModuleInfo provides metadata about a module
type ModuleInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
}
