package delivery

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"siem-event-generator/models"
)

const syslogAppName = "siem-event-generator"

// SyslogSender sends events via syslog (RFC 3164 or RFC 5424 over UDP or TCP).
// A failed write closes the connection and the next send dials again.
type SyslogSender struct {
	mu       sync.Mutex
	conn     net.Conn
	address  string
	config   models.DestinationConfig
	protocol string
}

// NewSyslogSender creates a new syslog sender
func NewSyslogSender(config models.DestinationConfig, protocol string) (*SyslogSender, error) {
	if config.Host == "" || config.Port <= 0 {
		return nil, fmt.Errorf("syslog host and port are required")
	}
	s := &SyslogSender{
		address:  net.JoinHostPort(config.Host, fmt.Sprintf("%d", config.Port)),
		config:   config,
		protocol: protocol,
	}
	if err := s.dial(); err != nil {
		return nil, fmt.Errorf("failed to connect to syslog server: %w", SafeError(err))
	}
	return s, nil
}

// dial opens the connection. The caller holds s.mu or is the constructor.
func (s *SyslogSender) dial() error {
	conn, err := net.DialTimeout(s.protocol, s.address, 10*time.Second)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Send sends an event via syslog
func (s *SyslogSender) Send(event *models.GeneratedEvent) error {
	return s.write(s.formatMessage(event))
}

func (s *SyslogSender) write(message string) error {
	if s.protocol == "tcp" {
		// TCP syslog requires newline delimiter; events are single-line
		message += "\n"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		if err := s.dial(); err != nil {
			return fmt.Errorf("reconnect failed: %w", SafeError(err))
		}
	}
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.conn.Write([]byte(message))
	if err != nil {
		s.conn.Close()
		s.conn = nil
		return SafeError(err)
	}
	return nil
}

// formatMessage formats the event as a syslog message
func (s *SyslogSender) formatMessage(event *models.GeneratedEvent) string {
	facility := 1 // user-level
	if s.config.Facility != nil {
		facility = *s.config.Facility
	}

	severity := 6 // informational
	if s.config.Severity != nil {
		severity = *s.config.Severity
	}

	priority := facility*8 + severity

	format := s.config.Format
	if format == "" {
		format = "rfc3164"
	}

	hostname := syslogAppName
	if event.Host != "" {
		hostname = event.Host
	}
	timestamp := event.Timestamp
	// A multi-line payload would be split into several messages by the receiver
	raw := strings.ReplaceAll(event.RawEvent, "\n", " ")

	if format == "rfc5424" {
		// RFC 5424 format
		return fmt.Sprintf("<%d>1 %s %s %s - - - %s",
			priority,
			timestamp.Format("2006-01-02T15:04:05.000000Z07:00"),
			hostname,
			syslogAppName,
			raw,
		)
	}

	// RFC 3164 (BSD) format
	return fmt.Sprintf("<%d>%s %s %s: %s",
		priority,
		timestamp.Format("Jan  2 15:04:05"),
		hostname,
		syslogAppName,
		raw,
	)
}

// Test tests the syslog connection
func (s *SyslogSender) Test() error {
	return s.write("<14>Jan  1 00:00:00 test " + syslogAppName + ": connection test")
}

// Close closes the syslog connection
func (s *SyslogSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
