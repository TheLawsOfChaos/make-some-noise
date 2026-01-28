package generators

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// PaloAltoGenerator generates Palo Alto Firewall events
type PaloAltoGenerator struct {
	BaseGenerator
}

func init() {
	Register(&PaloAltoGenerator{})
}

// GetEventType returns the event type for Palo Alto Firewall
func (g *PaloAltoGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "paloalto",
		Name:        "Palo Alto Firewall",
		Category:    "network",
		Description: "Palo Alto next-gen firewall traffic, threat, and URL logs",
		EventIDs:    []string{"TRAFFIC", "THREAT", "URL", "SYSTEM", "CONFIG"},
	}
}

// GetTemplates returns available templates for Palo Alto events
func (g *PaloAltoGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "traffic_allow",
			Name:        "Traffic Allow",
			Category:    "paloalto",
			EventID:     "TRAFFIC",
			Format:      "syslog",
			Description: "Allowed traffic session",
		},
		{
			ID:          "traffic_deny",
			Name:        "Traffic Deny",
			Category:    "paloalto",
			EventID:     "TRAFFIC",
			Format:      "syslog",
			Description: "Denied traffic session",
		},
		{
			ID:          "threat_virus",
			Name:        "Virus Detected",
			Category:    "paloalto",
			EventID:     "THREAT",
			Format:      "syslog",
			Description: "Virus threat detection",
		},
		{
			ID:          "threat_spyware",
			Name:        "Spyware Detected",
			Category:    "paloalto",
			EventID:     "THREAT",
			Format:      "syslog",
			Description: "Spyware threat detection",
		},
		{
			ID:          "url_block",
			Name:        "URL Block",
			Category:    "paloalto",
			EventID:     "URL",
			Format:      "syslog",
			Description: "Blocked URL access",
		},
		{
			ID:          "url_allow",
			Name:        "URL Allow",
			Category:    "paloalto",
			EventID:     "URL",
			Format:      "syslog",
			Description: "Allowed URL access",
		},
	}
}

// Generate creates a Palo Alto Firewall event
func (g *PaloAltoGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "traffic_allow":
		return g.generateTraffic("allow", overrides)
	case "traffic_deny":
		return g.generateTraffic("deny", overrides)
	case "threat_virus":
		return g.generateThreat("virus", overrides)
	case "threat_spyware":
		return g.generateThreat("spyware", overrides)
	case "url_block":
		return g.generateURL("block-url", overrides)
	case "url_allow":
		return g.generateURL("alert", overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *PaloAltoGenerator) randomFirewallHost() string {
	locations := []string{"dc1", "dc2", "hq", "branch", "edge"}
	return fmt.Sprintf("pa-%s-%02d", g.RandomChoice(locations), g.RandomInt(1, 10))
}

func (g *PaloAltoGenerator) randomZone() string {
	zones := []string{"trust", "untrust", "dmz", "vpn", "guest", "internal"}
	return g.RandomChoice(zones)
}

func (g *PaloAltoGenerator) randomApplication() string {
	apps := []string{"web-browsing", "ssl", "ssh", "dns", "ms-office365", "google-base", "youtube", "facebook", "smtp", "ftp"}
	return g.RandomChoice(apps)
}

func (g *PaloAltoGenerator) randomRule() string {
	rules := []string{"allow-outbound", "deny-inbound", "allow-internal", "vpn-access", "dmz-access", "block-malware"}
	return g.RandomChoice(rules)
}

func (g *PaloAltoGenerator) generateTraffic(action string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	hostname := g.randomFirewallHost()
	srcZone := g.randomZone()
	dstZone := g.randomZone()

	var srcIP, dstIP string
	var dstPort int
	if action == "allow" {
		srcIP = g.RandomIPv4Internal()
		dstIP = g.RandomIPv4External()
		dstPort = g.RandomCommonPort()
	} else {
		srcIP = g.RandomIPv4External()
		dstIP = g.RandomIPv4Internal()
		dstPortStr := g.RandomChoice([]string{"22", "3389", "445", "1433"})
		fmt.Sscanf(dstPortStr, "%d", &dstPort)
	}

	srcPort := g.RandomPort()
	sessionID := g.RandomInt(100000, 999999)
	bytes := g.RandomInt(1000, 1000000)
	packets := bytes / g.RandomInt(500, 1500)
	duration := g.RandomInt(1, 300)

	// TRAFFIC log format
	rawEvent := fmt.Sprintf("<%d>%s %s 1,2024/01/01 %s,0,%s,TRAFFIC,%s,2049,%s,%s/%s/%s/%d,%s/%s/%s/%d,%s,vsys1,%s,%s,ethernet1/1,ethernet1/2,%s,%d,%d,%d,%d,%s,%s,end,%s,%d,%d,n/a,0,0,0,0,0,0,0,0,0,N/A",
		14, // facility local0, severity info
		timestamp.Format("Jan 02 15:04:05"),
		hostname,
		timestamp.Format("15:04:05"),
		g.RandomString(16),
		action,
		g.RandomString(16),
		srcIP, "", "", srcPort,
		dstIP, "", "", dstPort,
		g.randomApplication(),
		srcZone,
		dstZone,
		g.randomRule(),
		sessionID,
		packets,
		bytes,
		duration,
		g.RandomChoice([]string{"tcp", "udp"}),
		action,
		g.randomApplication(),
		bytes,
		packets,
	)

	fields := map[string]interface{}{
		"log_type":     "TRAFFIC",
		"action":       action,
		"src_ip":       srcIP,
		"src_port":     srcPort,
		"dst_ip":       dstIP,
		"dst_port":     dstPort,
		"src_zone":     srcZone,
		"dst_zone":     dstZone,
		"application":  g.randomApplication(),
		"rule":         g.randomRule(),
		"session_id":   sessionID,
		"bytes":        bytes,
		"packets":      packets,
		"duration":     duration,
		"hostname":     hostname,
	}

	fields = g.ApplyOverrides(fields, overrides)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "paloalto",
		EventID:    "TRAFFIC",
		Timestamp:  timestamp,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "pan:traffic",
	}, nil
}

func (g *PaloAltoGenerator) generateThreat(threatType string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	hostname := g.randomFirewallHost()
	srcIP := g.RandomIPv4External()
	dstIP := g.RandomIPv4Internal()

	var threatName, severity string
	if threatType == "virus" {
		threatName = g.RandomChoice([]string{
			"Virus/Win32.WannaCry",
			"Virus/Win32.Emotet",
			"Virus/Win32.Locky",
			"Virus/Win32.TrickBot",
		})
		severity = "critical"
	} else {
		threatName = g.RandomChoice([]string{
			"Spyware/callback",
			"Spyware/DNS.tunneling",
			"Spyware/C2.beacon",
			"Spyware/keylogger",
		})
		severity = "high"
	}

	threatID := g.RandomInt(10000, 99999)
	sessionID := g.RandomInt(100000, 999999)

	rawEvent := fmt.Sprintf("<%d>%s %s 1,2024/01/01 %s,0,%s,THREAT,%s,2049,%s/%s/%s/%d,%s/%s/%s/%d,%s,vsys1,%s,%s,ethernet1/1,ethernet1/2,%s,%d,0,%s,0,%s,alert,%s,%s,%s,%d,%s,%d",
		10, // facility local0, severity warning
		timestamp.Format("Jan 02 15:04:05"),
		hostname,
		timestamp.Format("15:04:05"),
		g.RandomString(16),
		threatType,
		g.RandomString(16),
		srcIP, "", "", g.RandomPort(),
		dstIP, "", "", g.RandomCommonPort(),
		g.randomApplication(),
		g.randomZone(),
		g.randomZone(),
		g.randomRule(),
		sessionID,
		threatName,
		severity,
		"forward",
		threatType,
		g.RandomString(32),
		threatID,
		"client-to-server",
		g.RandomInt(100, 10000),
	)

	fields := map[string]interface{}{
		"log_type":    "THREAT",
		"threat_type": threatType,
		"threat_name": threatName,
		"threat_id":   threatID,
		"severity":    severity,
		"action":      "alert",
		"src_ip":      srcIP,
		"dst_ip":      dstIP,
		"session_id":  sessionID,
		"hostname":    hostname,
	}

	fields = g.ApplyOverrides(fields, overrides)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "paloalto",
		EventID:    "THREAT",
		Timestamp:  timestamp,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "pan:threat",
	}, nil
}

func (g *PaloAltoGenerator) generateURL(action string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	hostname := g.randomFirewallHost()
	srcIP := g.RandomIPv4Internal()
	dstIP := g.RandomIPv4External()

	categories := []string{"malware", "phishing", "adult", "gambling", "social-networking", "streaming-media", "proxy-avoidance"}
	category := g.RandomChoice(categories)

	domains := []string{
		"malware-site.evil.com",
		"phishing-login.fake.net",
		"blocked-category.example.com",
		"suspicious-domain.xyz",
	}
	url := fmt.Sprintf("https://%s/path/%s", g.RandomChoice(domains), g.RandomString(8))

	sessionID := g.RandomInt(100000, 999999)

	rawEvent := fmt.Sprintf("<%d>%s %s 1,2024/01/01 %s,0,%s,URL,%s,2049,%s/%s/%s/%d,%s/%s/%s/443,web-browsing,vsys1,%s,%s,ethernet1/1,ethernet1/2,%s,%d,0,%s,%s,%s,%s,%s,informational,forward,%d,container-page",
		14,
		timestamp.Format("Jan 02 15:04:05"),
		hostname,
		timestamp.Format("15:04:05"),
		g.RandomString(16),
		action,
		g.RandomString(16),
		srcIP, "", "", g.RandomPort(),
		dstIP, "", "",
		g.randomZone(),
		g.randomZone(),
		g.randomRule(),
		sessionID,
		url,
		category,
		action,
		"any",
		g.RandomString(32),
		g.RandomInt(1000, 50000),
	)

	fields := map[string]interface{}{
		"log_type":    "URL",
		"action":      action,
		"url":         url,
		"category":    category,
		"src_ip":      srcIP,
		"dst_ip":      dstIP,
		"session_id":  sessionID,
		"hostname":    hostname,
	}

	fields = g.ApplyOverrides(fields, overrides)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "paloalto",
		EventID:    "URL",
		Timestamp:  timestamp,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "pan:url",
	}, nil
}
