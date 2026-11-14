package delivery

import (
	"strings"
	"testing"
	"time"

	"siem-event-generator/models"
)

func TestSyslogFormatUsesEventHostAndAllowsZero(t *testing.T) {
	zero := 0
	s := &SyslogSender{config: models.DestinationConfig{Facility: &zero, Severity: &zero}}
	ev := &models.GeneratedEvent{RawEvent: "line one\nline two", Host: "fw01", Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	msg := s.formatMessage(ev)
	if !strings.HasPrefix(msg, "<0>Jan  2 03:04:05 fw01 ") {
		t.Fatalf("unexpected header: %q", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Fatal("payload newlines must be folded")
	}
	s.config.Format = "rfc5424"
	s.config.Facility, s.config.Severity = nil, nil
	if msg := s.formatMessage(ev); !strings.HasPrefix(msg, "<14>1 2026-01-02T03:04:05.000000Z fw01 "+syslogAppName+" - - - ") {
		t.Fatalf("unexpected rfc5424 header: %q", msg)
	}
}
