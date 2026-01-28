package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// MicrosoftDefenderGenerator generates Microsoft Defender for Endpoint events
type MicrosoftDefenderGenerator struct {
	BaseGenerator
}

func init() {
	Register(&MicrosoftDefenderGenerator{})
}

// GetEventType returns the event type for Microsoft Defender
func (g *MicrosoftDefenderGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "microsoft_defender",
		Name:        "Microsoft Defender for Endpoint",
		Category:    "endpoint",
		Description: "Microsoft Defender for Endpoint alerts and device events",
		EventIDs:    []string{"AlertEvidence", "DeviceEvents", "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents"},
	}
}

// GetTemplates returns available templates for Microsoft Defender events
func (g *MicrosoftDefenderGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "alert",
			Name:        "Security Alert",
			Category:    "microsoft_defender",
			EventID:     "AlertEvidence",
			Format:      "json",
			Description: "Defender security alert",
		},
		{
			ID:          "process_creation",
			Name:        "Process Creation",
			Category:    "microsoft_defender",
			EventID:     "DeviceProcessEvents",
			Format:      "json",
			Description: "Process creation event",
		},
		{
			ID:          "network_connection",
			Name:        "Network Connection",
			Category:    "microsoft_defender",
			EventID:     "DeviceNetworkEvents",
			Format:      "json",
			Description: "Network connection event",
		},
		{
			ID:          "file_creation",
			Name:        "File Creation",
			Category:    "microsoft_defender",
			EventID:     "DeviceFileEvents",
			Format:      "json",
			Description: "File creation event",
		},
		{
			ID:          "logon_event",
			Name:        "Logon Event",
			Category:    "microsoft_defender",
			EventID:     "DeviceEvents",
			Format:      "json",
			Description: "User logon event",
		},
		{
			ID:          "malware_detection",
			Name:        "Malware Detection",
			Category:    "microsoft_defender",
			EventID:     "AlertEvidence",
			Format:      "json",
			Description: "Malware detected by Defender AV",
		},
	}
}

// Generate creates a Microsoft Defender event
func (g *MicrosoftDefenderGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "alert":
		return g.generateAlert(overrides)
	case "process_creation":
		return g.generateProcessCreation(overrides)
	case "network_connection":
		return g.generateNetworkConnection(overrides)
	case "file_creation":
		return g.generateFileCreation(overrides)
	case "logon_event":
		return g.generateLogonEvent(overrides)
	case "malware_detection":
		return g.generateMalwareDetection(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *MicrosoftDefenderGenerator) randomDeviceID() string {
	return uuid.New().String()
}

func (g *MicrosoftDefenderGenerator) randomDeviceName() string {
	prefixes := []string{"WS", "LAPTOP", "SRV", "DC", "DESKTOP"}
	return fmt.Sprintf("%s-%s", g.RandomChoice(prefixes), g.RandomString(6))
}

func (g *MicrosoftDefenderGenerator) randomSHA256() string {
	return g.RandomString(64)
}

func (g *MicrosoftDefenderGenerator) randomSHA1() string {
	return g.RandomString(40)
}

func (g *MicrosoftDefenderGenerator) buildBaseEvent(actionType string) map[string]interface{} {
	timestamp := time.Now().UTC()
	deviceName := g.randomDeviceName()

	return map[string]interface{}{
		"Timestamp":       timestamp.Format(time.RFC3339),
		"DeviceId":        g.randomDeviceID(),
		"DeviceName":      deviceName,
		"ActionType":      actionType,
		"ReportId":        g.RandomInt(100000000, 999999999),
		"MachineGroup":    g.RandomChoice([]string{"Standard", "High-Value", "Servers", "Domain Controllers"}),
		"LocalIP":         g.RandomIPv4Internal(),
		"PublicIP":        g.RandomIPv4External(),
		"OSPlatform":      g.RandomChoice([]string{"Windows10", "Windows11", "WindowsServer2019", "WindowsServer2022"}),
		"OSBuild":         fmt.Sprintf("19045.%d", g.RandomInt(1000, 9999)),
	}
}

func (g *MicrosoftDefenderGenerator) generateAlert(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("AlertEvidence")

	alertTitles := []string{
		"Suspicious PowerShell command line",
		"Suspicious process executed",
		"Potential credential dumping activity",
		"Suspicious network connection",
		"Anomalous login detected",
		"Ransomware behavior detected",
	}

	severities := []string{"Low", "Medium", "High", "Critical"}
	categories := []string{"Execution", "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "LateralMovement", "Exfiltration"}

	event["AlertId"] = uuid.New().String()
	event["Title"] = g.RandomChoice(alertTitles)
	event["Severity"] = g.RandomChoice(severities)
	event["Category"] = g.RandomChoice(categories)
	event["Status"] = g.RandomChoice([]string{"New", "InProgress", "Resolved"})
	event["InvestigationId"] = g.RandomInt(10000, 99999)
	event["InvestigationState"] = g.RandomChoice([]string{"Running", "SuccessfullyRemediated", "Benign"})
	event["Classification"] = g.RandomChoice([]string{"TruePositive", "FalsePositive", "Unknown"})
	event["AccountName"] = g.RandomUsername()
	event["AccountDomain"] = g.RandomDomain()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_defender",
		EventID:    "AlertEvidence",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "ms:defender:endpoint",
	}, nil
}

func (g *MicrosoftDefenderGenerator) generateProcessCreation(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("ProcessCreated")

	event["FileName"] = g.RandomProcessName()
	event["FolderPath"] = g.RandomPath()
	event["SHA256"] = g.randomSHA256()
	event["SHA1"] = g.randomSHA1()
	event["ProcessId"] = g.RandomInt(1000, 65535)
	event["ProcessCommandLine"] = fmt.Sprintf("%s %s", g.RandomPath(), g.RandomChoice([]string{"-h", "--help", "/c", "-encodedcommand"}))
	event["ProcessCreationTime"] = timestamp.Format(time.RFC3339)
	event["InitiatingProcessFileName"] = g.RandomChoice([]string{"explorer.exe", "cmd.exe", "powershell.exe", "services.exe"})
	event["InitiatingProcessFolderPath"] = "C:\\Windows\\System32"
	event["InitiatingProcessId"] = g.RandomInt(1000, 65535)
	event["InitiatingProcessCommandLine"] = g.RandomPath()
	event["AccountName"] = g.RandomUsername()
	event["AccountDomain"] = g.RandomDomain()
	event["AccountSid"] = g.RandomSID()
	event["LogonId"] = g.RandomInt(100000, 999999)

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_defender",
		EventID:    "DeviceProcessEvents",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "ms:defender:endpoint",
	}, nil
}

func (g *MicrosoftDefenderGenerator) generateNetworkConnection(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("NetworkConnection")

	event["RemoteIP"] = g.RandomIPv4External()
	event["RemotePort"] = g.RandomChoice([]string{"443", "80", "22", "3389", "445"})
	event["LocalPort"] = g.RandomPort()
	event["Protocol"] = g.RandomChoice([]string{"Tcp", "Udp"})
	event["RemoteUrl"] = fmt.Sprintf("https://%s.%s", g.RandomString(8), g.RandomChoice([]string{"com", "net", "io"}))
	event["InitiatingProcessFileName"] = g.RandomChoice([]string{"chrome.exe", "firefox.exe", "outlook.exe", "powershell.exe"})
	event["InitiatingProcessFolderPath"] = g.RandomPath()
	event["InitiatingProcessId"] = g.RandomInt(1000, 65535)
	event["InitiatingProcessAccountName"] = g.RandomUsername()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_defender",
		EventID:    "DeviceNetworkEvents",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "ms:defender:endpoint",
	}, nil
}

func (g *MicrosoftDefenderGenerator) generateFileCreation(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("FileCreated")

	extensions := []string{".exe", ".dll", ".ps1", ".bat", ".vbs", ".docx", ".xlsx", ".pdf"}
	filename := fmt.Sprintf("%s%s", g.RandomString(8), g.RandomChoice(extensions))

	event["FileName"] = filename
	event["FolderPath"] = g.RandomPath()
	event["SHA256"] = g.randomSHA256()
	event["SHA1"] = g.randomSHA1()
	event["FileSize"] = g.RandomInt(1024, 10485760)
	event["InitiatingProcessFileName"] = g.RandomChoice([]string{"explorer.exe", "chrome.exe", "powershell.exe", "winword.exe"})
	event["InitiatingProcessFolderPath"] = g.RandomPath()
	event["InitiatingProcessId"] = g.RandomInt(1000, 65535)
	event["InitiatingProcessAccountName"] = g.RandomUsername()
	event["InitiatingProcessAccountDomain"] = g.RandomDomain()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_defender",
		EventID:    "DeviceFileEvents",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "ms:defender:endpoint",
	}, nil
}

func (g *MicrosoftDefenderGenerator) generateLogonEvent(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("LogonSuccess")

	logonTypes := []string{"Interactive", "Network", "RemoteInteractive", "Unlock", "CachedInteractive"}

	event["LogonType"] = g.RandomChoice(logonTypes)
	event["AccountName"] = g.RandomUsername()
	event["AccountDomain"] = g.RandomDomain()
	event["AccountSid"] = g.RandomSID()
	event["LogonId"] = g.RandomInt(100000, 999999)
	event["IsLocalAdmin"] = g.RandomInt(0, 1) == 1
	event["RemoteIP"] = g.RandomIPv4Internal()
	event["RemoteDeviceName"] = g.randomDeviceName()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_defender",
		EventID:    "DeviceEvents",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "ms:defender:endpoint",
	}, nil
}

func (g *MicrosoftDefenderGenerator) generateMalwareDetection(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("MalwareDetected")

	malwareNames := []string{
		"Trojan:Win32/AgentTesla.SM",
		"Ransom:Win32/WannaCrypt.A",
		"Backdoor:Win32/Emotet.A",
		"TrojanDownloader:O97M/Powdow.A",
		"Exploit:Win32/CVE-2021-40444.A",
		"Behavior:Win32/CobaltStrike.A",
	}

	event["ThreatName"] = g.RandomChoice(malwareNames)
	event["ThreatFamily"] = g.RandomChoice([]string{"AgentTesla", "Emotet", "CobaltStrike", "Mimikatz", "WannaCry"})
	event["Severity"] = g.RandomChoice([]string{"Low", "Medium", "High", "Severe"})
	event["Category"] = g.RandomChoice([]string{"Trojan", "Ransomware", "Backdoor", "Exploit", "HackTool"})
	event["FileName"] = g.RandomProcessName()
	event["FolderPath"] = g.RandomPath()
	event["SHA256"] = g.randomSHA256()
	event["ActionType"] = g.RandomChoice([]string{"Quarantine", "Remove", "Clean", "Block"})
	event["InitialDetectionSource"] = g.RandomChoice([]string{"RealTimeProtection", "CloudProtection", "User", "IOAV"})
	event["AccountName"] = g.RandomUsername()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_defender",
		EventID:    "AlertEvidence",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "ms:defender:endpoint",
	}, nil
}
