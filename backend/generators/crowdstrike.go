package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// CrowdStrikeGenerator generates CrowdStrike Falcon events
type CrowdStrikeGenerator struct {
	BaseGenerator
}

func init() {
	Register(&CrowdStrikeGenerator{})
}

// GetEventType returns the event type for CrowdStrike Falcon
func (g *CrowdStrikeGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "crowdstrike",
		Name:        "CrowdStrike Falcon",
		Category:    "endpoint",
		Description: "CrowdStrike EDR detections, process events, and threat intelligence",
		EventIDs:    []string{"DetectionSummaryEvent", "ProcessRollup2", "NetworkConnectIP4", "DnsRequest", "FileWritten"},
	}
}

// GetTemplates returns available templates for CrowdStrike Falcon events
func (g *CrowdStrikeGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "detection",
			Name:        "Detection Event",
			Category:    "crowdstrike",
			EventID:     "DetectionSummaryEvent",
			Format:      "json",
			Description: "Falcon threat detection",
		},
		{
			ID:          "process",
			Name:        "Process Event",
			Category:    "crowdstrike",
			EventID:     "ProcessRollup2",
			Format:      "json",
			Description: "Process execution event",
		},
		{
			ID:          "network",
			Name:        "Network Connection",
			Category:    "crowdstrike",
			EventID:     "NetworkConnectIP4",
			Format:      "json",
			Description: "Network connection event",
		},
		{
			ID:          "dns",
			Name:        "DNS Request",
			Category:    "crowdstrike",
			EventID:     "DnsRequest",
			Format:      "json",
			Description: "DNS query event",
		},
		{
			ID:          "file_write",
			Name:        "File Written",
			Category:    "crowdstrike",
			EventID:     "FileWritten",
			Format:      "json",
			Description: "File write event",
		},
		{
			ID:          "auth_activity",
			Name:        "Authentication Activity",
			Category:    "crowdstrike",
			EventID:     "UserLogon",
			Format:      "json",
			Description: "User authentication event",
		},
	}
}

// Generate creates a CrowdStrike Falcon event
func (g *CrowdStrikeGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "detection":
		return g.generateDetection(overrides)
	case "process":
		return g.generateProcess(overrides)
	case "network":
		return g.generateNetwork(overrides)
	case "dns":
		return g.generateDNS(overrides)
	case "file_write":
		return g.generateFileWrite(overrides)
	case "auth_activity":
		return g.generateAuthActivity(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *CrowdStrikeGenerator) randomAID() string {
	return g.RandomString(32)
}

func (g *CrowdStrikeGenerator) randomCID() string {
	return g.RandomString(32)
}

func (g *CrowdStrikeGenerator) randomSHA256() string {
	return g.RandomString(64)
}

func (g *CrowdStrikeGenerator) randomComputerName() string {
	prefixes := []string{"WS", "LAPTOP", "SRV", "DC", "DESKTOP"}
	return fmt.Sprintf("%s-%s", g.RandomChoice(prefixes), g.RandomString(6))
}

func (g *CrowdStrikeGenerator) randomTactic() (string, string) {
	tactics := []struct {
		id   string
		name string
	}{
		{"TA0001", "Initial Access"},
		{"TA0002", "Execution"},
		{"TA0003", "Persistence"},
		{"TA0004", "Privilege Escalation"},
		{"TA0005", "Defense Evasion"},
		{"TA0006", "Credential Access"},
		{"TA0007", "Discovery"},
		{"TA0008", "Lateral Movement"},
		{"TA0010", "Exfiltration"},
		{"TA0011", "Command and Control"},
	}
	t := tactics[g.RandomInt(0, len(tactics)-1)]
	return t.id, t.name
}

func (g *CrowdStrikeGenerator) randomTechnique() (string, string) {
	techniques := []struct {
		id   string
		name string
	}{
		{"T1059.001", "PowerShell"},
		{"T1059.003", "Windows Command Shell"},
		{"T1053.005", "Scheduled Task"},
		{"T1547.001", "Registry Run Keys"},
		{"T1078", "Valid Accounts"},
		{"T1003.001", "LSASS Memory"},
		{"T1021.001", "Remote Desktop Protocol"},
		{"T1071.001", "Web Protocols"},
		{"T1486", "Data Encrypted for Impact"},
	}
	t := techniques[g.RandomInt(0, len(techniques)-1)]
	return t.id, t.name
}

func (g *CrowdStrikeGenerator) buildBaseEvent(eventType string) map[string]interface{} {
	timestamp := time.Now().UTC()
	return map[string]interface{}{
		"metadata": map[string]interface{}{
			"customerIDString": g.randomCID(),
			"offset":           g.RandomInt(100000, 999999),
			"eventType":        eventType,
			"eventCreationTime": timestamp.UnixMilli(),
			"version":          "1.0",
		},
		"event": map[string]interface{}{
			"aid":          g.randomAID(),
			"cid":          g.randomCID(),
			"ComputerName": g.randomComputerName(),
			"LocalIP":      g.RandomIPv4Internal(),
			"MAC":          g.RandomMAC(),
			"timestamp":    timestamp.Format(time.RFC3339),
		},
	}
}

func (g *CrowdStrikeGenerator) generateDetection(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	base := g.buildBaseEvent("DetectionSummaryEvent")

	tacticID, tacticName := g.randomTactic()
	techniqueID, techniqueName := g.randomTechnique()

	severities := []string{"Low", "Medium", "High", "Critical"}
	severity := g.RandomChoice(severities)

	detectionNames := []string{
		"Malicious PowerShell Execution",
		"Credential Dumping Detected",
		"Suspicious Process Injection",
		"Known Malware Hash Detected",
		"Ransomware Behavior Detected",
		"Lateral Movement Detected",
	}

	base["event"].(map[string]interface{})["DetectId"] = uuid.New().String()
	base["event"].(map[string]interface{})["DetectName"] = g.RandomChoice(detectionNames)
	base["event"].(map[string]interface{})["DetectDescription"] = fmt.Sprintf("Detection triggered: %s via %s", techniqueName, tacticName)
	base["event"].(map[string]interface{})["Severity"] = severity
	base["event"].(map[string]interface{})["SeverityName"] = severity
	base["event"].(map[string]interface{})["Tactic"] = tacticName
	base["event"].(map[string]interface{})["TacticId"] = tacticID
	base["event"].(map[string]interface{})["Technique"] = techniqueName
	base["event"].(map[string]interface{})["TechniqueId"] = techniqueID
	base["event"].(map[string]interface{})["FileName"] = g.RandomProcessName()
	base["event"].(map[string]interface{})["FilePath"] = g.RandomPath()
	base["event"].(map[string]interface{})["SHA256String"] = g.randomSHA256()
	base["event"].(map[string]interface{})["UserName"] = g.RandomUsername()
	base["event"].(map[string]interface{})["ParentImageFileName"] = g.RandomChoice([]string{"explorer.exe", "cmd.exe", "powershell.exe", "svchost.exe"})

	fields := g.ApplyOverrides(base, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "crowdstrike",
		EventID:    "DetectionSummaryEvent",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "crowdstrike:falcon:json",
	}, nil
}

func (g *CrowdStrikeGenerator) generateProcess(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	base := g.buildBaseEvent("ProcessRollup2")

	base["event"].(map[string]interface{})["ImageFileName"] = g.RandomProcessName()
	base["event"].(map[string]interface{})["CommandLine"] = fmt.Sprintf("%s %s", g.RandomPath(), g.RandomChoice([]string{"-h", "--version", "/c whoami", "-encodedcommand", ""}))
	base["event"].(map[string]interface{})["SHA256HashData"] = g.randomSHA256()
	base["event"].(map[string]interface{})["ParentBaseFileName"] = g.RandomChoice([]string{"explorer.exe", "cmd.exe", "powershell.exe", "services.exe"})
	base["event"].(map[string]interface{})["ParentCommandLine"] = g.RandomPath()
	base["event"].(map[string]interface{})["UserName"] = g.RandomUsername()
	base["event"].(map[string]interface{})["UserSid"] = g.RandomSID()
	base["event"].(map[string]interface{})["TargetProcessId"] = g.RandomInt(1000, 65535)
	base["event"].(map[string]interface{})["ParentProcessId"] = g.RandomInt(1000, 65535)

	fields := g.ApplyOverrides(base, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "crowdstrike",
		EventID:    "ProcessRollup2",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "crowdstrike:falcon:json",
	}, nil
}

func (g *CrowdStrikeGenerator) generateNetwork(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	base := g.buildBaseEvent("NetworkConnectIP4")

	base["event"].(map[string]interface{})["RemoteAddressIP4"] = g.RandomIPv4External()
	base["event"].(map[string]interface{})["RemotePort"] = g.RandomChoice([]string{"443", "80", "22", "3389", "8080"})
	base["event"].(map[string]interface{})["LocalAddressIP4"] = g.RandomIPv4Internal()
	base["event"].(map[string]interface{})["LocalPort"] = g.RandomPort()
	base["event"].(map[string]interface{})["Protocol"] = g.RandomChoice([]string{"TCP", "UDP"})
	base["event"].(map[string]interface{})["ConnectionDirection"] = g.RandomChoice([]string{"0", "1"}) // 0=outbound, 1=inbound
	base["event"].(map[string]interface{})["ImageFileName"] = g.RandomProcessName()

	fields := g.ApplyOverrides(base, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "crowdstrike",
		EventID:    "NetworkConnectIP4",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "crowdstrike:falcon:json",
	}, nil
}

func (g *CrowdStrikeGenerator) generateDNS(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	base := g.buildBaseEvent("DnsRequest")

	domains := []string{
		"www.google.com", "api.microsoft.com", "cdn.cloudflare.com",
		"update.example.com", "telemetry.company.com", "login.office365.com",
	}

	base["event"].(map[string]interface{})["DomainName"] = g.RandomChoice(domains)
	base["event"].(map[string]interface{})["RequestType"] = g.RandomChoice([]string{"A", "AAAA", "CNAME", "MX", "TXT"})
	base["event"].(map[string]interface{})["ImageFileName"] = g.RandomChoice([]string{"chrome.exe", "firefox.exe", "outlook.exe", "svchost.exe"})

	fields := g.ApplyOverrides(base, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "crowdstrike",
		EventID:    "DnsRequest",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "crowdstrike:falcon:json",
	}, nil
}

func (g *CrowdStrikeGenerator) generateFileWrite(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	base := g.buildBaseEvent("FileWritten")

	extensions := []string{".exe", ".dll", ".ps1", ".bat", ".vbs", ".docx", ".xlsx"}
	filename := fmt.Sprintf("%s%s", g.RandomString(8), g.RandomChoice(extensions))

	base["event"].(map[string]interface{})["TargetFileName"] = filename
	base["event"].(map[string]interface{})["TargetDirectoryName"] = g.RandomPath()
	base["event"].(map[string]interface{})["SHA256HashData"] = g.randomSHA256()
	base["event"].(map[string]interface{})["Size"] = g.RandomInt(1024, 10485760)
	base["event"].(map[string]interface{})["ImageFileName"] = g.RandomChoice([]string{"explorer.exe", "chrome.exe", "powershell.exe", "word.exe"})
	base["event"].(map[string]interface{})["UserName"] = g.RandomUsername()

	fields := g.ApplyOverrides(base, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "crowdstrike",
		EventID:    "FileWritten",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "crowdstrike:falcon:json",
	}, nil
}

func (g *CrowdStrikeGenerator) generateAuthActivity(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	base := g.buildBaseEvent("UserLogon")

	logonTypes := []struct {
		code int
		name string
	}{
		{2, "Interactive"},
		{3, "Network"},
		{10, "RemoteInteractive"},
		{7, "Unlock"},
	}
	logonType := logonTypes[g.RandomInt(0, len(logonTypes)-1)]

	base["event"].(map[string]interface{})["UserName"] = g.RandomUsername()
	base["event"].(map[string]interface{})["UserSid"] = g.RandomSID()
	base["event"].(map[string]interface{})["LogonType"] = logonType.code
	base["event"].(map[string]interface{})["LogonTypeName"] = logonType.name
	base["event"].(map[string]interface{})["AuthenticationPackage"] = g.RandomChoice([]string{"NTLM", "Kerberos", "Negotiate"})
	base["event"].(map[string]interface{})["LogonDomain"] = g.RandomDomain()
	base["event"].(map[string]interface{})["RemoteAddressIP4"] = g.RandomIPv4Internal()

	fields := g.ApplyOverrides(base, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "crowdstrike",
		EventID:    "UserLogon",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "crowdstrike:falcon:json",
	}, nil
}
