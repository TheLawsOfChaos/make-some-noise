package generators

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// AWSVPCFlowGenerator generates AWS VPC Flow Log events
type AWSVPCFlowGenerator struct {
	BaseGenerator
}

func init() {
	Register(&AWSVPCFlowGenerator{})
}

// GetEventType returns the event type for AWS VPC Flow Logs
func (g *AWSVPCFlowGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "aws_vpcflow",
		Name:        "AWS VPC Flow Logs",
		Category:    "cloud",
		Description: "AWS VPC Flow Logs - network traffic metadata for VPCs",
		EventIDs:    []string{"ACCEPT", "REJECT"},
	}
}

// GetTemplates returns available templates for AWS VPC Flow Logs
func (g *AWSVPCFlowGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "accept_inbound",
			Name:        "Accept Inbound",
			Category:    "aws_vpcflow",
			EventID:     "ACCEPT",
			Format:      "text",
			Description: "Accepted inbound traffic",
		},
		{
			ID:          "accept_outbound",
			Name:        "Accept Outbound",
			Category:    "aws_vpcflow",
			EventID:     "ACCEPT",
			Format:      "text",
			Description: "Accepted outbound traffic",
		},
		{
			ID:          "reject_inbound",
			Name:        "Reject Inbound",
			Category:    "aws_vpcflow",
			EventID:     "REJECT",
			Format:      "text",
			Description: "Rejected inbound traffic",
		},
		{
			ID:          "reject_outbound",
			Name:        "Reject Outbound",
			Category:    "aws_vpcflow",
			EventID:     "REJECT",
			Format:      "text",
			Description: "Rejected outbound traffic",
		},
	}
}

// Generate creates an AWS VPC Flow Log event
func (g *AWSVPCFlowGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "accept_inbound":
		return g.generateFlow("ACCEPT", "inbound", overrides)
	case "accept_outbound":
		return g.generateFlow("ACCEPT", "outbound", overrides)
	case "reject_inbound":
		return g.generateFlow("REJECT", "inbound", overrides)
	case "reject_outbound":
		return g.generateFlow("REJECT", "outbound", overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *AWSVPCFlowGenerator) randomAccountID() string {
	return fmt.Sprintf("%012d", g.RandomInt(100000000000, 999999999999))
}

func (g *AWSVPCFlowGenerator) randomENI() string {
	return fmt.Sprintf("eni-%s", g.RandomString(17))
}

func (g *AWSVPCFlowGenerator) generateFlow(action, direction string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()

	var srcAddr, dstAddr string
	var srcPort, dstPort int

	if direction == "inbound" {
		srcAddr = g.RandomIPv4External()
		dstAddr = g.RandomIPv4Internal()
		srcPort = g.RandomPort()
		dstPortStr := g.RandomChoice([]string{"22", "443", "80", "3389", "3306"})
		fmt.Sscanf(dstPortStr, "%d", &dstPort)
	} else {
		srcAddr = g.RandomIPv4Internal()
		dstAddr = g.RandomIPv4External()
		srcPort = g.RandomPort()
		dstPortStr := g.RandomChoice([]string{"443", "80", "53", "123"})
		fmt.Sscanf(dstPortStr, "%d", &dstPort)
	}

	protocol := g.RandomChoice([]string{"6", "17"}) // TCP or UDP
	packets := g.RandomInt(1, 1000)
	bytes := packets * g.RandomInt(40, 1500)
	startTime := timestamp.Add(-time.Duration(g.RandomInt(1, 60)) * time.Second).Unix()
	endTime := timestamp.Unix()
	eni := g.randomENI()

	// VPC Flow Log format version 2
	rawEvent := fmt.Sprintf("2 %s %s %s %s %d %d %s %d %d %d %d %s -",
		accountID,
		eni,
		srcAddr,
		dstAddr,
		srcPort,
		dstPort,
		protocol,
		packets,
		bytes,
		startTime,
		endTime,
		action,
	)

	fields := map[string]interface{}{
		"version":      2,
		"account_id":   accountID,
		"interface_id": eni,
		"srcaddr":      srcAddr,
		"dstaddr":      dstAddr,
		"srcport":      srcPort,
		"dstport":      dstPort,
		"protocol":     protocol,
		"packets":      packets,
		"bytes":        bytes,
		"start":        startTime,
		"end":          endTime,
		"action":       action,
		"log_status":   "OK",
	}

	fields = g.ApplyOverrides(fields, overrides)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_vpcflow",
		EventID:    action,
		Timestamp:  timestamp,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "aws:cloudwatchlogs:vpcflow",
	}, nil
}
