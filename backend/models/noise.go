package models

import "time"

// NoiseConfig represents the configuration for noise generation
type NoiseConfig struct {
	ID             string               `json:"id,omitempty"`
	Name           string               `json:"name,omitempty"`
	DestinationID  string               `json:"destination_id,omitempty"`  // Default destination (fallback)
	RatePerSecond  float64              `json:"rate_per_second" binding:"required,min=0.1,max=10000"`
	EnabledSources []EnabledEventSource `json:"enabled_sources" binding:"required,min=1"`
	CreatedAt      time.Time            `json:"created_at,omitempty"`
	UpdatedAt      time.Time            `json:"updated_at,omitempty"`
}

// EnabledEventSource represents an enabled event type with weight
type EnabledEventSource struct {
	EventTypeID   string   `json:"event_type_id" binding:"required"`
	TemplateIDs   []string `json:"template_ids,omitempty"`   // Empty means all templates
	Weight        int      `json:"weight"`                   // 1-100, relative frequency
	Enabled       bool     `json:"enabled"`
	DestinationID string   `json:"destination_id,omitempty"` // Per-source destination (overrides global)
}

// NoiseStatus represents the current state of noise generation
type NoiseStatus struct {
	Running       bool         `json:"running"`
	StartedAt     *time.Time   `json:"started_at,omitempty"`
	CurrentConfig *NoiseConfig `json:"current_config,omitempty"`
	Stats         NoiseStats   `json:"stats"`
}

// NoiseStats represents generation statistics
type NoiseStats struct {
	TotalGenerated  int64            `json:"total_generated"`
	TotalSent       int64            `json:"total_sent"`
	TotalErrors     int64            `json:"total_errors"`
	EventsPerSecond float64          `json:"events_per_second"`
	LastEventAt     *time.Time       `json:"last_event_at,omitempty"`
	ByEventType     map[string]int64 `json:"by_event_type"`
	ByTemplate      map[string]int64 `json:"by_template"`
	DurationSeconds int64            `json:"duration_seconds"`
	ErrorSamples    []string         `json:"error_samples,omitempty"` // Last 5 errors
}

// NoiseStartRequest represents a request to start noise generation
type NoiseStartRequest struct {
	DestinationID  string               `json:"destination_id,omitempty"`  // Default destination (fallback)
	RatePerSecond  float64              `json:"rate_per_second" binding:"required,min=0.1,max=10000"`
	EnabledSources []EnabledEventSource `json:"enabled_sources" binding:"required,min=1"`
}

// NoiseUpdateRequest represents a request to update running configuration
type NoiseUpdateRequest struct {
	RatePerSecond  *float64              `json:"rate_per_second,omitempty"`
	EnabledSources []EnabledEventSource  `json:"enabled_sources,omitempty"`
}

// EventSourceTree represents the hierarchical structure of event types
type EventSourceTree struct {
	Categories map[string][]EventSourceInfo `json:"categories"`
}

// EventSourceInfo contains event type with its templates
type EventSourceInfo struct {
	EventType EventType       `json:"event_type"`
	Templates []EventTemplate `json:"templates"`
}
