package delivery

import (
	"fmt"
	"net"
	"time"

	"siem-event-generator/models"
)

// SyslogSender sends events via syslog
type SyslogSender struct {
	conn     net.Conn
	config   models.DestinationConfig
	protocol string
}

// NewSyslogSender creates a new syslog sender
func NewSyslogSender(config models.DestinationConfig, protocol string) (*SyslogSender, error) {
	address := fmt.Sprintf("%s:%d", config.Host, config.Port)

	var conn net.Conn
	var err error

	if protocol == "tcp" {
		conn, err = net.DialTimeout("tcp", address, 10*time.Second)
	} else {
		conn, err = net.DialTimeout("udp", address, 10*time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog server: %w", err)
	}

	return &SyslogSender{
		conn:     conn,
		config:   config,
		protocol: protocol,
	}, nil
}

// Send sends an event via syslog
func (s *SyslogSender) Send(event *models.GeneratedEvent) error {
	message := s.formatMessage(event)

	if s.protocol == "tcp" {
		// TCP syslog requires newline delimiter
		message += "\n"
	}

	_, err := s.conn.Write([]byte(message))
	return err
}

// formatMessage formats the event as a syslog message
func (s *SyslogSender) formatMessage(event *models.GeneratedEvent) string {
	facility := s.config.Facility
	if facility == 0 {
		facility = 1 // user-level
	}

	severity := s.config.Severity
	if severity == 0 {
		severity = 6 // informational
	}

	priority := facility*8 + severity

	format := s.config.Format
	if format == "" {
		format = "rfc3164"
	}

	hostname := "siem-event-generator"
	timestamp := event.Timestamp

	if format == "rfc5424" {
		// RFC 5424 format
		return fmt.Sprintf("<%d>1 %s %s siem-event-generator - - - %s",
			priority,
			timestamp.Format("2006-01-02T15:04:05.000000Z07:00"),
			hostname,
			event.RawEvent,
		)
	}

	// RFC 3164 (BSD) format
	return fmt.Sprintf("<%d>%s %s siem-event-generator: %s",
		priority,
		timestamp.Format("Jan  2 15:04:05"),
		hostname,
		event.RawEvent,
	)
}

// Test tests the syslog connection
func (s *SyslogSender) Test() error {
	testMessage := "<14>Jan  1 00:00:00 test siem-event-generator: connection test"

	if s.protocol == "tcp" {
		testMessage += "\n"
	}

	// Set a deadline for the test
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer s.conn.SetWriteDeadline(time.Time{})

	_, err := s.conn.Write([]byte(testMessage))
	return err
}

// Close closes the syslog connection
func (s *SyslogSender) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
