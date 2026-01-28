package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// CiscoFirepowerGenerator generates Cisco Firepower IDS/IPS events
type CiscoFirepowerGenerator struct {
	BaseGenerator
}

func init() {
	Register(&CiscoFirepowerGenerator{})
}

// GetEventType returns the event type for Cisco Firepower
func (g *CiscoFirepowerGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "cisco_firepower",
		Name:        "Cisco Firepower",
		Category:    "network",
		Description: "Cisco Firepower Threat Defense (FTD) intrusion, connection, and malware events",
		EventIDs:    []string{"intrusion", "connection", "file", "malware"},
	}
}

// GetTemplates returns available templates for Cisco Firepower events
func (g *CiscoFirepowerGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "intrusion",
			Name:        "Intrusion Event",
			Category:    "cisco_firepower",
			EventID:     "intrusion",
			Format:      "json",
			Description: "IDS/IPS intrusion detection event",
		},
		{
			ID:          "connection",
			Name:        "Connection Event",
			Category:    "cisco_firepower",
			EventID:     "connection",
			Format:      "json",
			Description: "Network connection event",
		},
		{
			ID:          "file",
			Name:        "File Event",
			Category:    "cisco_firepower",
			EventID:     "file",
			Format:      "json",
			Description: "File detection event",
		},
		{
			ID:          "malware",
			Name:        "Malware Event",
			Category:    "cisco_firepower",
			EventID:     "malware",
			Format:      "json",
			Description: "Malware detection event",
		},
	}
}

// Generate creates a Cisco Firepower event
func (g *CiscoFirepowerGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "intrusion":
		return g.generateIntrusion(overrides)
	case "connection":
		return g.generateConnection(overrides)
	case "file":
		return g.generateFile(overrides)
	case "malware":
		return g.generateMalware(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// RandomSID generates a Snort-style SID
func (g *CiscoFirepowerGenerator) RandomSID() int {
	return g.RandomInt(1000000, 9999999)
}

// RandomGID generates a Snort-style GID
func (g *CiscoFirepowerGenerator) RandomGID() int {
	gids := []int{1, 3, 116, 119, 120, 122, 123, 124, 125, 126, 129, 131, 133, 134, 135, 136, 137, 138, 139, 140}
	return gids[g.RandomInt(0, len(gids)-1)]
}

// RandomClassification returns a random intrusion classification
func (g *CiscoFirepowerGenerator) RandomClassification() string {
	classifications := []string{
		"attempted-recon",
		"attempted-user",
		"attempted-admin",
		"successful-recon-limited",
		"successful-user",
		"successful-admin",
		"trojan-activity",
		"web-application-attack",
		"policy-violation",
		"misc-attack",
	}
	return g.RandomChoice(classifications)
}

// RandomPriority returns a random priority level
func (g *CiscoFirepowerGenerator) RandomPriority() int {
	return g.RandomInt(1, 4)
}

// generateIntrusion creates an intrusion event
func (g *CiscoFirepowerGenerator) generateIntrusion(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	messages := []string{
		"INDICATOR-COMPROMISE Suspicious DNS query",
		"MALWARE-CNC Win.Trojan.Agent outbound connection",
		"EXPLOIT-KIT Angler exploit kit landing page",
		"SERVER-WEBAPP SQL injection attempt",
		"BROWSER-IE Microsoft Internet Explorer use-after-free attempt",
		"PROTOCOL-DNS DNS query for known malware domain",
		"FILE-EXECUTABLE Portable Executable download",
		"INDICATOR-SCAN SSH brute force attempt",
		"POLICY-OTHER Cryptocurrency mining traffic detected",
		"MALWARE-BACKDOOR Remote access trojan connection",
	}

	actions := []string{"Blocked", "Would Have Blocked", "Allowed"}

	fields := map[string]interface{}{
		"timestamp":         now.Format(time.RFC3339Nano),
		"event_type":        "intrusion",
		"sensor_id":         g.RandomString(8),
		"sensor_name":       fmt.Sprintf("FTD-%s", g.RandomString(4)),
		"policy":            fmt.Sprintf("IPS_Policy_%s", g.RandomChoice([]string{"Production", "Staging", "Default"})),
		"rule_id":           g.RandomSID(),
		"generator_id":      g.RandomGID(),
		"revision":          g.RandomInt(1, 20),
		"classification":    g.RandomClassification(),
		"priority":          g.RandomPriority(),
		"message":           g.RandomChoice(messages),
		"src_ip":            g.RandomIPv4External(),
		"src_port":          g.RandomPort(),
		"dst_ip":            g.RandomIPv4Internal(),
		"dst_port":          g.RandomCommonPort(),
		"protocol":          g.RandomChoice([]string{"TCP", "UDP", "ICMP"}),
		"action":            g.RandomChoice(actions),
		"impact":            g.RandomChoice([]string{"Unknown", "Potentially Vulnerable", "Vulnerable", "Not Vulnerable"}),
		"blocked":           g.RandomInt(0, 1) == 1,
		"impact_flag":       g.RandomInt(0, 4),
		"ingress_interface": fmt.Sprintf("ethernet1/%d", g.RandomInt(1, 8)),
		"egress_interface":  fmt.Sprintf("ethernet1/%d", g.RandomInt(1, 8)),
		"src_zone":          g.RandomChoice([]string{"Outside", "DMZ", "Internet"}),
		"dst_zone":          g.RandomChoice([]string{"Inside", "Trusted", "Internal"}),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_firepower",
		EventID:    "intrusion",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "cisco:firepower:syslog",
	}, nil
}

// generateConnection creates a connection event
func (g *CiscoFirepowerGenerator) generateConnection(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	actions := []string{"Allow", "Block", "Interactive Block", "Reset", "Trust"}
	reasons := []string{"IP Block", "URL Block", "DNS Block", "Intrusion Block", "File Block", "-"}

	initiatorBytes := g.RandomInt(100, 100000000)
	responderBytes := g.RandomInt(100, 100000000)
	initiatorPkts := initiatorBytes / g.RandomInt(500, 1500)
	responderPkts := responderBytes / g.RandomInt(500, 1500)

	fields := map[string]interface{}{
		"timestamp":          now.Format(time.RFC3339Nano),
		"event_type":         "connection",
		"sensor_id":          g.RandomString(8),
		"sensor_name":        fmt.Sprintf("FTD-%s", g.RandomString(4)),
		"policy":             fmt.Sprintf("AC_Policy_%s", g.RandomChoice([]string{"Production", "Staging", "Default"})),
		"src_ip":             g.RandomIPv4Internal(),
		"src_port":           g.RandomPort(),
		"dst_ip":             g.RandomIPv4External(),
		"dst_port":           g.RandomCommonPort(),
		"protocol":           g.RandomChoice([]string{"TCP", "UDP"}),
		"action":             g.RandomChoice(actions),
		"reason":             g.RandomChoice(reasons),
		"ingress_interface":  fmt.Sprintf("ethernet1/%d", g.RandomInt(1, 8)),
		"egress_interface":   fmt.Sprintf("ethernet1/%d", g.RandomInt(1, 8)),
		"src_zone":           g.RandomChoice([]string{"Inside", "Trusted", "Internal"}),
		"dst_zone":           g.RandomChoice([]string{"Outside", "DMZ", "Internet"}),
		"initiator_bytes":    initiatorBytes,
		"responder_bytes":    responderBytes,
		"initiator_packets":  initiatorPkts,
		"responder_packets":  responderPkts,
		"application":        g.RandomChoice([]string{"HTTPS", "HTTP", "DNS", "SSH", "SMB", "FTP", "SMTP"}),
		"url":                fmt.Sprintf("https://%s.com/%s", g.RandomString(8), g.RandomString(12)),
		"url_category":       g.RandomChoice([]string{"Business", "Technology", "Unknown", "Malware", "Social Networking"}),
		"web_application":    g.RandomChoice([]string{"Google", "Microsoft", "Amazon", "Facebook", "Unknown"}),
		"client":             g.RandomChoice([]string{"Chrome", "Firefox", "Edge", "Safari", "Unknown"}),
		"client_version":     fmt.Sprintf("%d.%d.%d", g.RandomInt(80, 120), g.RandomInt(0, 99), g.RandomInt(0, 9999)),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_firepower",
		EventID:    "connection",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "cisco:firepower:syslog",
	}, nil
}

// generateFile creates a file event
func (g *CiscoFirepowerGenerator) generateFile(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	fileTypes := []string{"PDF", "MSEXE", "MSOLE2", "ZIP", "RAR", "DOCX", "XLSX", "JS", "VBS", "PS1"}
	fileActions := []string{"Detect", "Block", "Malware Block", "Cloud Lookup", "Archive Block"}
	directions := []string{"Download", "Upload"}

	fields := map[string]interface{}{
		"timestamp":       now.Format(time.RFC3339Nano),
		"event_type":      "file",
		"sensor_id":       g.RandomString(8),
		"sensor_name":     fmt.Sprintf("FTD-%s", g.RandomString(4)),
		"policy":          fmt.Sprintf("File_Policy_%s", g.RandomChoice([]string{"Production", "Staging", "Default"})),
		"src_ip":          g.RandomIPv4External(),
		"src_port":        g.RandomPort(),
		"dst_ip":          g.RandomIPv4Internal(),
		"dst_port":        g.RandomCommonPort(),
		"protocol":        "TCP",
		"file_name":       fmt.Sprintf("%s.%s", g.RandomString(10), g.RandomChoice([]string{"exe", "dll", "pdf", "docx", "zip"})),
		"file_size":       g.RandomInt(1000, 10000000),
		"file_type":       g.RandomChoice(fileTypes),
		"file_action":     g.RandomChoice(fileActions),
		"sha256":          g.RandomString(64),
		"direction":       g.RandomChoice(directions),
		"application":     g.RandomChoice([]string{"HTTP", "HTTPS", "FTP", "SMB", "SMTP"}),
		"url":             fmt.Sprintf("https://%s.com/files/%s", g.RandomString(8), g.RandomString(12)),
		"disposition":     g.RandomChoice([]string{"Unknown", "Clean", "Malware", "Custom Detection", "Unavailable"}),
		"threat_score":    g.RandomInt(0, 100),
		"archive_depth":   g.RandomInt(0, 3),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_firepower",
		EventID:    "file",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "cisco:firepower:syslog",
	}, nil
}

// generateMalware creates a malware event
func (g *CiscoFirepowerGenerator) generateMalware(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	malwareNames := []string{
		"W32.GenericKD",
		"Trojan.GenericKD",
		"Win.Trojan.Agent",
		"Doc.Dropper.Agent",
		"Win.Ransomware.Locky",
		"Win.Packed.Themida",
		"JS.Downloader.Nemucod",
		"VBS.Downloader.Trojan",
		"Win.Spyware.Agent",
		"Win.Coinminer.Agent",
	}

	threatTypes := []string{
		"Trojan",
		"Ransomware",
		"Dropper",
		"Downloader",
		"Spyware",
		"Adware",
		"Coinminer",
		"Backdoor",
		"Worm",
		"Exploit",
	}

	fields := map[string]interface{}{
		"timestamp":        now.Format(time.RFC3339Nano),
		"event_type":       "malware",
		"sensor_id":        g.RandomString(8),
		"sensor_name":      fmt.Sprintf("FTD-%s", g.RandomString(4)),
		"policy":           fmt.Sprintf("Malware_Policy_%s", g.RandomChoice([]string{"Production", "Staging", "Default"})),
		"src_ip":           g.RandomIPv4External(),
		"src_port":         g.RandomPort(),
		"dst_ip":           g.RandomIPv4Internal(),
		"dst_port":         g.RandomCommonPort(),
		"protocol":         "TCP",
		"file_name":        fmt.Sprintf("%s.exe", g.RandomString(10)),
		"file_size":        g.RandomInt(10000, 5000000),
		"sha256":           g.RandomString(64),
		"malware_name":     g.RandomChoice(malwareNames),
		"threat_type":      g.RandomChoice(threatTypes),
		"threat_score":     g.RandomInt(50, 100),
		"disposition":      "Malware",
		"action":           g.RandomChoice([]string{"Block", "Detect", "Quarantine"}),
		"amp_disposition":  g.RandomChoice([]string{"Malicious", "High Risk", "Unknown"}),
		"amp_threat_name":  g.RandomChoice(malwareNames),
		"application":      g.RandomChoice([]string{"HTTP", "HTTPS", "SMTP", "FTP"}),
		"direction":        g.RandomChoice([]string{"Download", "Upload"}),
		"retrospective":    g.RandomInt(0, 1) == 1,
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_firepower",
		EventID:    "malware",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "cisco:firepower:syslog",
	}, nil
}
