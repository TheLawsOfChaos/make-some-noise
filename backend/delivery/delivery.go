package delivery

import (
	"fmt"

	"siem-event-generator/models"
)

// Sender interface for all delivery methods
type Sender interface {
	Send(event *models.GeneratedEvent) error
	Test() error
	Close() error
}

// GetSender returns the appropriate sender for a destination
func GetSender(dest *models.Destination) (Sender, error) {
	switch dest.Type {
	case models.DestinationTypeSyslogUDP:
		return NewSyslogSender(dest.Config, "udp")
	case models.DestinationTypeSyslogTCP:
		return NewSyslogSender(dest.Config, "tcp")
	case models.DestinationTypeHEC:
		return NewHECSender(dest.Config)
	case models.DestinationTypeFile:
		return NewFileSender(dest.Config)
	default:
		return nil, fmt.Errorf("unknown destination type: %s", dest.Type)
	}
}
