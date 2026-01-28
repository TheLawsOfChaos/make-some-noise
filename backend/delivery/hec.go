package delivery

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"siem-event-generator/models"
)

// HECSender sends events to Splunk HTTP Event Collector
type HECSender struct {
	client *http.Client
	config models.DestinationConfig
	buffer []*hecEvent
}

// hecEvent represents a Splunk HEC event payload
type hecEvent struct {
	Time       float64                `json:"time"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	Sourcetype string                 `json:"sourcetype,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Event      interface{}            `json:"event"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

// hecResponse represents a Splunk HEC response
type hecResponse struct {
	Text               string `json:"text"`
	Code               int    `json:"code"`
	InvalidEventNumber int    `json:"invalid-event-number,omitempty"`
	AckID              int    `json:"ackId,omitempty"`
}

// NewHECSender creates a new HEC sender
func NewHECSender(config models.DestinationConfig) (*HECSender, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("HEC URL is required")
	}

	if config.Token == "" {
		return nil, fmt.Errorf("HEC token is required")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	batchSize := config.BatchSize
	if batchSize == 0 {
		batchSize = 100
	}

	return &HECSender{
		client: client,
		config: config,
		buffer: make([]*hecEvent, 0, batchSize),
	}, nil
}

// Send sends an event to HEC
func (h *HECSender) Send(event *models.GeneratedEvent) error {
	hecEvt := &hecEvent{
		Time:       float64(event.Timestamp.Unix()) + float64(event.Timestamp.Nanosecond())/1e9,
		Host:       "siem-event-generator",
		Source:     h.config.Source,
		Sourcetype: event.Sourcetype,
		Index:      h.config.Index,
		Event:      event.RawEvent,
	}

	// Override sourcetype if specified in config
	if h.config.Sourcetype != "" {
		hecEvt.Sourcetype = h.config.Sourcetype
	}

	h.buffer = append(h.buffer, hecEvt)

	// Flush if buffer is full
	if len(h.buffer) >= h.config.BatchSize || h.config.BatchSize == 0 {
		return h.flush()
	}

	return nil
}

// flush sends all buffered events to HEC
func (h *HECSender) flush() error {
	if len(h.buffer) == 0 {
		return nil
	}

	// Build the request body (newline-delimited JSON)
	var body bytes.Buffer
	for _, evt := range h.buffer {
		data, err := json.Marshal(evt)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}
		body.Write(data)
		body.WriteByte('\n')
	}

	req, err := http.NewRequest("POST", h.config.URL, &body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+h.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var hecResp hecResponse
		json.Unmarshal(respBody, &hecResp)
		return fmt.Errorf("HEC returned status %d: %s", resp.StatusCode, hecResp.Text)
	}

	// Clear the buffer
	h.buffer = h.buffer[:0]

	return nil
}

// Test tests the HEC connection
func (h *HECSender) Test() error {
	testEvent := &hecEvent{
		Time:       float64(time.Now().Unix()),
		Host:       "siem-event-generator",
		Source:     "test",
		Sourcetype: "_json",
		Event:      "Connection test event",
	}

	data, err := json.Marshal(testEvent)
	if err != nil {
		return fmt.Errorf("failed to marshal test event: %w", err)
	}

	req, err := http.NewRequest("POST", h.config.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+h.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to HEC: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication failed: invalid HEC token")
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var hecResp hecResponse
		json.Unmarshal(respBody, &hecResp)
		return fmt.Errorf("HEC returned status %d: %s", resp.StatusCode, hecResp.Text)
	}

	return nil
}

// Close flushes any remaining events and closes the sender
func (h *HECSender) Close() error {
	return h.flush()
}
