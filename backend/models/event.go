package models

import "time"

// EventType represents a category of security events
type EventType struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	EventIDs    []string `json:"event_ids,omitempty"`
}

// EventField defines a field within an event template
type EventField struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Generator   string        `json:"generator,omitempty"`
	Description string        `json:"description,omitempty"`
	Default     interface{}   `json:"default,omitempty"`
	Choices     []interface{} `json:"choices,omitempty"`
	Required    bool          `json:"required,omitempty"`
	Min         int           `json:"min,omitempty"`
	Max         int           `json:"max,omitempty"`
	Length      int           `json:"length,omitempty"`
	Format      string        `json:"format,omitempty"`
}

// EventTemplate defines the structure for generating events
type EventTemplate struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Category       string       `json:"category"`
	EventID        string       `json:"event_id,omitempty"`
	Format         string       `json:"format"` // xml, json, syslog, cef
	Description    string       `json:"description,omitempty"`
	Sourcetype     string       `json:"sourcetype,omitempty"`
	Fields         []EventField `json:"fields,omitempty"`
	OutputTemplate string       `json:"output_template,omitempty"`
}

// GeneratedEvent represents a single generated event
type GeneratedEvent struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	EventID    string                 `json:"event_id,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	RawEvent   string                 `json:"raw_event"`
	Fields     map[string]interface{} `json:"fields"`
	Sourcetype string                 `json:"sourcetype"`
}

// GenerateRequest represents a request to generate events
type GenerateRequest struct {
	EventType     string                 `json:"event_type" binding:"required"`
	EventID       string                 `json:"event_id,omitempty"`
	Count         int                    `json:"count" binding:"required,min=1,max=10000"`
	DestinationID string                 `json:"destination_id,omitempty"`
	Overrides     map[string]interface{} `json:"overrides,omitempty"`
	RatePerSecond int                    `json:"rate_per_second,omitempty"`
}

// GenerateResponse represents the response from event generation
type GenerateResponse struct {
	Success       bool             `json:"success"`
	EventsCreated int              `json:"events_created"`
	EventsSent    int              `json:"events_sent"`
	Destination   string           `json:"destination,omitempty"`
	Errors        []string         `json:"errors,omitempty"`
	Preview       []GeneratedEvent `json:"preview,omitempty"`
}

// PreviewRequest represents a request to preview a single event
type PreviewRequest struct {
	EventType string                 `json:"event_type" binding:"required"`
	EventID   string                 `json:"event_id,omitempty"`
	Overrides map[string]interface{} `json:"overrides,omitempty"`
}

// EventTypeSchema represents the schema for a specific event type
type EventTypeSchema struct {
	EventType EventType     `json:"event_type"`
	Templates []EventTemplate `json:"templates"`
}
