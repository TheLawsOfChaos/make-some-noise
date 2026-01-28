package generators

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// WindowsSecurityGenerator generates Windows Security events
type WindowsSecurityGenerator struct {
	BaseGenerator
}

func init() {
	Register(&WindowsSecurityGenerator{})
}

// GetEventType returns the event type for Windows Security
func (g *WindowsSecurityGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "windows_security",
		Name:        "Windows Security",
		Category:    "windows",
		Description: "Windows Security Event Log events including logon, process, and privilege events",
		EventIDs:    []string{"4624", "4625", "4688", "4672", "4720", "4726", "4728", "4732"},
	}
}

// GetTemplates returns available templates for Windows Security events
func (g *WindowsSecurityGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "4624",
			Name:        "Successful Logon",
			Category:    "windows_security",
			EventID:     "4624",
			Format:      "xml",
			Description: "An account was successfully logged on",
		},
		{
			ID:          "4625",
			Name:        "Failed Logon",
			Category:    "windows_security",
			EventID:     "4625",
			Format:      "xml",
			Description: "An account failed to log on",
		},
		{
			ID:          "4688",
			Name:        "Process Creation",
			Category:    "windows_security",
			EventID:     "4688",
			Format:      "xml",
			Description: "A new process has been created",
		},
		{
			ID:          "4672",
			Name:        "Special Privileges Assigned",
			Category:    "windows_security",
			EventID:     "4672",
			Format:      "xml",
			Description: "Special privileges assigned to new logon",
		},
		{
			ID:          "4720",
			Name:        "User Account Created",
			Category:    "windows_security",
			EventID:     "4720",
			Format:      "xml",
			Description: "A user account was created",
		},
	}
}

// WindowsEvent represents a Windows Event Log structure
type WindowsEvent struct {
	XMLName xml.Name `xml:"Event"`
	Xmlns   string   `xml:"xmlns,attr"`
	System  WindowsEventSystem
	EventData WindowsEventData
}

type WindowsEventSystem struct {
	XMLName       xml.Name `xml:"System"`
	Provider      WindowsEventProvider
	EventID       int    `xml:"EventID"`
	Version       int    `xml:"Version"`
	Level         int    `xml:"Level"`
	Task          int    `xml:"Task"`
	Opcode        int    `xml:"Opcode"`
	Keywords      string `xml:"Keywords"`
	TimeCreated   WindowsTimeCreated
	EventRecordID int64  `xml:"EventRecordID"`
	Correlation   string `xml:"Correlation"`
	Execution     WindowsExecution
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
	Security      WindowsSecurity
}

type WindowsEventProvider struct {
	XMLName string `xml:"Provider"`
	Name    string `xml:"Name,attr"`
	Guid    string `xml:"Guid,attr"`
}

type WindowsTimeCreated struct {
	XMLName    string `xml:"TimeCreated"`
	SystemTime string `xml:"SystemTime,attr"`
}

type WindowsExecution struct {
	XMLName   string `xml:"Execution"`
	ProcessID int    `xml:"ProcessID,attr"`
	ThreadID  int    `xml:"ThreadID,attr"`
}

type WindowsSecurity struct {
	XMLName string `xml:"Security"`
	UserID  string `xml:"UserID,attr,omitempty"`
}

type WindowsEventData struct {
	XMLName xml.Name `xml:"EventData"`
	Data    []WindowsDataItem
}

type WindowsDataItem struct {
	XMLName xml.Name `xml:"Data"`
	Name    string   `xml:"Name,attr"`
	Value   string   `xml:",chardata"`
}

// Generate creates a Windows Security event
func (g *WindowsSecurityGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "4624":
		return g.generate4624(overrides)
	case "4625":
		return g.generate4625(overrides)
	case "4688":
		return g.generate4688(overrides)
	case "4672":
		return g.generate4672(overrides)
	case "4720":
		return g.generate4720(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// generate4624 creates a successful logon event
func (g *WindowsSecurityGenerator) generate4624(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	logonTypes := []int{2, 3, 7, 10, 11}
	logonType := logonTypes[g.RandomInt(0, len(logonTypes)-1)]

	fields := map[string]interface{}{
		"SubjectUserSid":        g.RandomSID(),
		"SubjectUserName":       g.RandomUsername(),
		"SubjectDomainName":     g.RandomDomain(),
		"SubjectLogonId":        fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"TargetUserSid":         g.RandomSID(),
		"TargetUserName":        g.RandomUsername(),
		"TargetDomainName":      g.RandomDomain(),
		"TargetLogonId":         fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"LogonType":             logonType,
		"LogonProcessName":      "NtLmSsp",
		"AuthenticationPackageName": "NTLM",
		"WorkstationName":       g.RandomHostname(),
		"LogonGuid":             g.RandomGUID(),
		"TransmittedServices":   "-",
		"LmPackageName":         "NTLM V2",
		"KeyLength":             128,
		"ProcessId":             g.RandomInt(4, 65535),
		"ProcessName":           "C:\\Windows\\System32\\lsass.exe",
		"IpAddress":             g.RandomIPv4Internal(),
		"IpPort":                g.RandomPort(),
		"ImpersonationLevel":    "%%1833",
		"RestrictedAdminMode":   "-",
		"TargetOutboundUserName": "-",
		"TargetOutboundDomainName": "-",
		"VirtualAccount":        "%%1843",
		"TargetLinkedLogonId":   "0x0",
		"ElevatedToken":         "%%1842",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(4624, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_security",
		EventID:    "4624",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4625 creates a failed logon event
func (g *WindowsSecurityGenerator) generate4625(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	failureReasons := []string{"%%2313", "%%2304", "%%2308", "%%2309", "%%2310"}
	statuses := []string{"0xc000006d", "0xc000006a", "0xc0000234", "0xc0000072"}

	fields := map[string]interface{}{
		"SubjectUserSid":         "S-1-0-0",
		"SubjectUserName":        "-",
		"SubjectDomainName":      "-",
		"SubjectLogonId":         "0x0",
		"TargetUserSid":          "S-1-0-0",
		"TargetUserName":         g.RandomUsername(),
		"TargetDomainName":       g.RandomDomain(),
		"Status":                 g.RandomChoice(statuses),
		"FailureReason":          g.RandomChoice(failureReasons),
		"SubStatus":              "0x0",
		"LogonType":              g.RandomInt(2, 11),
		"LogonProcessName":       "NtLmSsp",
		"AuthenticationPackageName": "NTLM",
		"WorkstationName":        g.RandomHostname(),
		"TransmittedServices":    "-",
		"LmPackageName":          "-",
		"KeyLength":              0,
		"ProcessId":              0,
		"ProcessName":            "-",
		"IpAddress":              g.RandomIPv4External(),
		"IpPort":                 g.RandomPort(),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(4625, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_security",
		EventID:    "4625",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4688 creates a process creation event
func (g *WindowsSecurityGenerator) generate4688(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	fields := map[string]interface{}{
		"SubjectUserSid":     g.RandomSID(),
		"SubjectUserName":    g.RandomUsername(),
		"SubjectDomainName":  g.RandomDomain(),
		"SubjectLogonId":     fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"NewProcessId":       fmt.Sprintf("0x%x", g.RandomInt(1000, 65535)),
		"NewProcessName":     g.RandomPath(),
		"TokenElevationType": "%%1936",
		"ProcessId":          fmt.Sprintf("0x%x", g.RandomInt(1000, 65535)),
		"CommandLine":        g.RandomPath(),
		"TargetUserSid":      g.RandomSID(),
		"TargetUserName":     g.RandomUsername(),
		"TargetDomainName":   g.RandomDomain(),
		"TargetLogonId":      fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"ParentProcessName":  "C:\\Windows\\System32\\cmd.exe",
		"MandatoryLabel":     "S-1-16-8192",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(4688, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_security",
		EventID:    "4688",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4672 creates a special privileges assigned event
func (g *WindowsSecurityGenerator) generate4672(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	privileges := []string{
		"SeSecurityPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeTakeOwnershipPrivilege",
		"SeDebugPrivilege",
		"SeSystemEnvironmentPrivilege",
		"SeLoadDriverPrivilege",
		"SeImpersonatePrivilege",
		"SeDelegateSessionUserImpersonatePrivilege",
		"SeEnableDelegationPrivilege",
	}

	numPrivs := g.RandomInt(1, 5)
	selectedPrivs := ""
	for i := 0; i < numPrivs; i++ {
		if i > 0 {
			selectedPrivs += "\n\t\t\t"
		}
		selectedPrivs += g.RandomChoice(privileges)
	}

	fields := map[string]interface{}{
		"SubjectUserSid":   g.RandomSID(),
		"SubjectUserName":  g.RandomUsername(),
		"SubjectDomainName": g.RandomDomain(),
		"SubjectLogonId":   fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":    selectedPrivs,
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(4672, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_security",
		EventID:    "4672",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4720 creates a user account created event
func (g *WindowsSecurityGenerator) generate4720(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	newUser := g.RandomUsername()

	fields := map[string]interface{}{
		"TargetUserName":     newUser,
		"TargetDomainName":   g.RandomDomain(),
		"TargetSid":          g.RandomSID(),
		"SubjectUserSid":     g.RandomSID(),
		"SubjectUserName":    g.RandomUsername(),
		"SubjectDomainName":  g.RandomDomain(),
		"SubjectLogonId":     fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":      "-",
		"SamAccountName":     newUser,
		"DisplayName":        newUser,
		"UserPrincipalName":  fmt.Sprintf("%s@%s.local", newUser, g.RandomDomain()),
		"HomeDirectory":      "-",
		"HomePath":           "-",
		"ScriptPath":         "-",
		"ProfilePath":        "-",
		"UserWorkstations":   "-",
		"PasswordLastSet":    now.Format("1/2/2006 3:04:05 PM"),
		"AccountExpires":     "%%1794",
		"PrimaryGroupId":     "513",
		"AllowedToDelegateTo": "-",
		"OldUacValue":        "0x0",
		"NewUacValue":        "0x15",
		"UserAccountControl": "%%2080\n\t\t%%2082\n\t\t%%2084",
		"UserParameters":     "-",
		"SidHistory":         "-",
		"LogonHours":         "%%1793",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(4720, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_security",
		EventID:    "4720",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// buildEvent creates the common Windows Event structure
func (g *WindowsSecurityGenerator) buildEvent(eventID int, timestamp time.Time, fields map[string]interface{}) WindowsEvent {
	dataItems := make([]WindowsDataItem, 0)
	for name, value := range fields {
		dataItems = append(dataItems, WindowsDataItem{
			Name:  name,
			Value: fmt.Sprintf("%v", value),
		})
	}

	return WindowsEvent{
		Xmlns: "http://schemas.microsoft.com/win/2004/08/events/event",
		System: WindowsEventSystem{
			Provider: WindowsEventProvider{
				Name: "Microsoft-Windows-Security-Auditing",
				Guid: "{54849625-5478-4994-A5BA-3E3B0328C30D}",
			},
			EventID:       eventID,
			Version:       2,
			Level:         0,
			Task:          12544,
			Opcode:        0,
			Keywords:      "0x8020000000000000",
			TimeCreated:   WindowsTimeCreated{SystemTime: timestamp.Format("2006-01-02T15:04:05.000000000Z")},
			EventRecordID: int64(g.RandomInt(100000, 99999999)),
			Execution:     WindowsExecution{ProcessID: g.RandomInt(4, 1000), ThreadID: g.RandomInt(100, 10000)},
			Channel:       "Security",
			Computer:      g.RandomFQDN(),
		},
		EventData: WindowsEventData{Data: dataItems},
	}
}
