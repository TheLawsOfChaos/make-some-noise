package delivery

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"siem-event-generator/models"
)

const (
	defaultBatchSize = 100
	flushInterval    = time.Second
	maxBackoff       = 30 * time.Second
)

// HECSender sends events to Splunk HTTP Event Collector in batches.
//
// Events are buffered and flushed when the batch is full, once a second, or
// on Close. A failed flush keeps the batch for the next attempt with an
// exponential backoff; the buffer is capped at ten batches and the oldest
// events are dropped past that, counted in Dropped().
type HECSender struct {
	client    *http.Client
	config    models.DestinationConfig
	batchSize int

	mu        sync.Mutex
	buffer    []*hecEvent
	backoff   time.Duration
	nextTry   time.Time
	dropped   int64
	failed    int64
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
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
			InsecureSkipVerify: config.InsecureSkipVerify, //nolint:gosec // operator opt-in for self-signed collectors
			MinVersion:         tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		// Never follow a redirect: the Authorization header must not travel
		// to a host the operator did not configure.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	batchSize := config.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}

	h := &HECSender{
		client:    client,
		config:    config,
		batchSize: batchSize,
		buffer:    make([]*hecEvent, 0, batchSize),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go h.flushLoop()
	return h, nil
}

// Send queues an event. It returns an error when a flush it triggered failed
// (the batch is kept and retried with backoff) or when the event pushed the
// oldest one out of a full buffer.
func (h *HECSender) Send(event *models.GeneratedEvent) error {
	host := "siem-event-generator"
	if event.Host != "" {
		host = event.Host
	}

	hecEvt := &hecEvent{
		Time:       float64(event.Timestamp.Unix()) + float64(event.Timestamp.Nanosecond())/1e9,
		Host:       host,
		Source:     h.config.Source,
		Sourcetype: event.Sourcetype,
		Index:      h.config.Index,
		Event:      event.RawEvent,
	}

	// Override sourcetype if specified in config
	if h.config.Sourcetype != "" {
		hecEvt.Sourcetype = h.config.Sourcetype
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var dropErr error
	if len(h.buffer) >= h.batchSize*10 {
		// ponytail: fixed cap of ten batches; make it configurable if a lab needs more slack
		h.buffer = h.buffer[1:]
		dropErr = fmt.Errorf("HEC buffer full, oldest event dropped (%d dropped so far)", atomic.AddInt64(&h.dropped, 1))
	}
	h.buffer = append(h.buffer, hecEvt)

	if len(h.buffer) >= h.batchSize {
		if err := h.flushLocked(); err != nil {
			return err
		}
	}
	return dropErr
}

// Dropped returns the number of events discarded because the buffer was full.
func (h *HECSender) Dropped() int64 { return atomic.LoadInt64(&h.dropped) }

// FailedFlushes returns the number of batch sends that failed.
func (h *HECSender) FailedFlushes() int64 { return atomic.LoadInt64(&h.failed) }

func (h *HECSender) flushLoop() {
	defer close(h.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			h.mu.Lock()
			if err := h.flushLocked(); err != nil {
				log.Printf("hec: %v", err)
			}
			h.mu.Unlock()
		}
	}
}

// flushLocked sends the buffered events. The caller holds h.mu.
func (h *HECSender) flushLocked() error {
	if len(h.buffer) == 0 || time.Now().Before(h.nextTry) {
		return nil
	}

	err := h.post(h.buffer)
	if err != nil {
		atomic.AddInt64(&h.failed, 1)
		if h.backoff == 0 {
			h.backoff = time.Second
		} else if h.backoff < maxBackoff {
			h.backoff *= 2
		}
		h.nextTry = time.Now().Add(h.backoff)
		return fmt.Errorf("flush of %d events failed, retrying in %s: %w", len(h.buffer), h.backoff, err)
	}

	h.buffer = h.buffer[:0]
	h.backoff = 0
	h.nextTry = time.Time{}
	return nil
}

// post sends one batch as newline-delimited JSON.
func (h *HECSender) post(events []*hecEvent) error {
	var body bytes.Buffer
	for _, evt := range events {
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
		return fmt.Errorf("failed to send request: %w", SafeError(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var hecResp hecResponse
		json.Unmarshal(respBody, &hecResp)
		return fmt.Errorf("HEC returned status %d: %s", resp.StatusCode, hecResp.Text)
	}
	return nil
}

// Test tests the HEC connection
func (h *HECSender) Test() error {
	testEvent := &hecEvent{
		Time:       float64(time.Now().Unix()),
		Host:       "siem-event-generator",
		Source:     "test",
		Sourcetype: "_json",
		Index:      h.config.Index,
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
		return fmt.Errorf("failed to connect to HEC: %w", SafeError(err))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("authentication failed: invalid HEC token")
	case http.StatusForbidden:
		return fmt.Errorf("authentication failed: HEC token disabled")
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return fmt.Errorf("HEC URL redirects (status %d); configure the final URL", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var hecResp hecResponse
	json.Unmarshal(respBody, &hecResp)
	return fmt.Errorf("HEC returned status %d: %s", resp.StatusCode, hecResp.Text)
}

// Close stops the timed flush and sends whatever is still buffered once.
func (h *HECSender) Close() error {
	var err error
	h.closeOnce.Do(func() {
		close(h.stop)
		<-h.done
		h.mu.Lock()
		defer h.mu.Unlock()
		h.nextTry = time.Time{}
		err = h.flushLocked()
	})
	return err
}
