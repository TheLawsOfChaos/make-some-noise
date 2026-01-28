package models

import "time"

// DestinationType defines the type of destination
type DestinationType string

const (
	DestinationTypeSyslogUDP DestinationType = "syslog_udp"
	DestinationTypeSyslogTCP DestinationType = "syslog_tcp"
	DestinationTypeHEC       DestinationType = "hec"
	DestinationTypeFile      DestinationType = "file"
)

// Destination represents a target for sending generated events
type Destination struct {
	ID          string          `json:"id"`
	Name        string          `json:"name" binding:"required"`
	Type        DestinationType `json:"type" binding:"required"`
	Description string          `json:"description,omitempty"`
	Config      DestinationConfig `json:"config" binding:"required"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	LastUsed    *time.Time      `json:"last_used,omitempty"`
	EventsSent  int64           `json:"events_sent"`
}

// DestinationConfig holds configuration specific to each destination type
type DestinationConfig struct {
	// Syslog configuration
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Facility int    `json:"facility,omitempty"` // 0-23
	Severity int    `json:"severity,omitempty"` // 0-7
	Format   string `json:"format,omitempty"`   // rfc3164, rfc5424

	// HEC configuration
	URL         string `json:"url,omitempty"`
	Token       string `json:"token,omitempty"`
	Index       string `json:"index,omitempty"`
	Source      string `json:"source,omitempty"`
	Sourcetype  string `json:"sourcetype,omitempty"`
	VerifySSL   bool   `json:"verify_ssl,omitempty"`
	BatchSize   int    `json:"batch_size,omitempty"`

	// File configuration
	FilePath   string `json:"file_path,omitempty"`
	MaxSizeMB  int    `json:"max_size_mb,omitempty"`
	RotateKeep int    `json:"rotate_keep,omitempty"`
}

// TestConnectionRequest represents a request to test a destination connection
type TestConnectionRequest struct {
	Type   DestinationType   `json:"type" binding:"required"`
	Config DestinationConfig `json:"config" binding:"required"`
}

// TestConnectionResponse represents the result of a connection test
type TestConnectionResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	LatencyMs   int64  `json:"latency_ms,omitempty"`
	Error       string `json:"error,omitempty"`
}

// DestinationStats represents statistics for a destination
type DestinationStats struct {
	TotalEventsSent   int64     `json:"total_events_sent"`
	LastEventSentAt   *time.Time `json:"last_event_sent_at,omitempty"`
	FailedEvents      int64     `json:"failed_events"`
	AvgLatencyMs      float64   `json:"avg_latency_ms"`
}
