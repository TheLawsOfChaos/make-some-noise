package delivery

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"siem-event-generator/models"
)

type hecServer struct {
	*httptest.Server
	mu       sync.Mutex
	batches  [][]string
	fail     atomic.Bool
	requests atomic.Int64
}

func newHECServer(t *testing.T) *hecServer {
	s := &hecServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		if r.Header.Get("Authorization") != "Splunk tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s.fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var lines []string
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		s.mu.Lock()
		s.batches = append(s.batches, lines)
		s.mu.Unlock()
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *hecServer) batchSizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, len(s.batches))
	for i, b := range s.batches {
		out[i] = len(b)
	}
	return out
}

func event(i int) *models.GeneratedEvent {
	return &models.GeneratedEvent{RawEvent: `{"n":` + string(rune('0'+i%10)) + `}`, Sourcetype: "t", Timestamp: time.Now()}
}

func TestHECBatchesByCount(t *testing.T) {
	srv := newHECServer(t)
	h, err := NewHECSender(models.DestinationConfig{URL: srv.URL, Token: "tok", BatchSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := h.Send(event(i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := srv.batchSizes(); len(got) != 2 || got[0] != 3 || got[1] != 3 {
		t.Fatalf("expected two batches of 3 before close, got %v", got)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if got := srv.batchSizes(); len(got) != 3 || got[2] != 1 {
		t.Fatalf("expected the last event flushed on close, got %v", got)
	}
}

func TestHECTimedFlush(t *testing.T) {
	srv := newHECServer(t)
	h, err := NewHECSender(models.DestinationConfig{URL: srv.URL, Token: "tok", BatchSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.Send(event(1))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.batchSizes()) == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("a single event was not flushed by the timer")
}

func TestHECRetriesWithBackoffAndDrops(t *testing.T) {
	srv := newHECServer(t)
	srv.fail.Store(true)
	h, err := NewHECSender(models.DestinationConfig{URL: srv.URL, Token: "tok", BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// 2 events: first flush fails, the error is reported and the batch kept
	h.Send(event(0))
	if err := h.Send(event(1)); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected the flush failure to be reported, got %v", err)
	}
	if h.FailedFlushes() != 1 {
		t.Fatalf("expected 1 failed flush, got %d", h.FailedFlushes())
	}
	// During backoff no request is made
	before := srv.requests.Load()
	h.Send(event(2))
	h.Send(event(3))
	if srv.requests.Load() != before {
		t.Fatal("flush attempted during backoff")
	}
	// Cap is 10 batches = 20 events; push past it and expect drops
	for i := 0; i < 25; i++ {
		h.Send(event(i))
	}
	if h.Dropped() == 0 {
		t.Fatal("expected drops once the buffer was full")
	}
	// Collector recovers: after the backoff the buffer is delivered
	srv.fail.Store(false)
	h.mu.Lock()
	h.nextTry = time.Time{}
	h.mu.Unlock()
	h.Send(event(9))
	if got := srv.batchSizes(); len(got) != 1 || got[0] != 20 {
		t.Fatalf("expected the retained 20 events in one batch, got %v", got)
	}
	if h.Dropped() != 10 {
		t.Fatalf("expected 10 dropped (29 sent, 20 kept minus the one that triggered the flush), got %d", h.Dropped())
	}
}

func TestHECDoesNotFollowRedirects(t *testing.T) {
	leaked := atomic.Bool{}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer sink.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	h, _ := NewHECSender(models.DestinationConfig{URL: redirector.URL, Token: "tok"})
	defer h.Close()
	if err := h.Test(); err == nil {
		t.Fatal("redirecting collector must fail the test")
	}
	if leaked.Load() {
		t.Fatal("token was sent to the redirect target")
	}
}

func TestHECTestReportsAuthFailures(t *testing.T) {
	srv := newHECServer(t)
	h, _ := NewHECSender(models.DestinationConfig{URL: srv.URL, Token: "wrong"})
	defer h.Close()
	if err := h.Test(); err == nil || err.Error() != "authentication failed: invalid HEC token" {
		t.Fatalf("unexpected: %v", err)
	}
}
