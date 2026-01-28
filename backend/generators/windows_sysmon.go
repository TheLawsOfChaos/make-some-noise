package generators

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// WindowsSysmonGenerator generates Windows Sysmon events
type WindowsSysmonGenerator struct {
	BaseGenerator
}

func init() {
	Register(&WindowsSysmonGenerator{})
}

// GetEventType returns the event type for Windows Sysmon
func (g *WindowsSysmonGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "windows_sysmon",
		Name:        "Windows Sysmon",
		Category:    "windows",
		Description: "Windows Sysmon events for process, network, and file monitoring",
		EventIDs:    []string{"1", "3", "7", "8", "10", "11", "12", "13", "22"},
	}
}

// GetTemplates returns available templates for Sysmon events
func (g *WindowsSysmonGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "1",
			Name:        "Process Create",
			Category:    "windows_sysmon",
			EventID:     "1",
			Format:      "xml",
			Description: "Process creation event with command line and hash information",
		},
		{
			ID:          "3",
			Name:        "Network Connection",
			Category:    "windows_sysmon",
			EventID:     "3",
			Format:      "xml",
			Description: "TCP/UDP network connection detected",
		},
		{
			ID:          "7",
			Name:        "Image Loaded",
			Category:    "windows_sysmon",
			EventID:     "7",
			Format:      "xml",
			Description: "DLL or image loaded by a process",
		},
		{
			ID:          "8",
			Name:        "CreateRemoteThread",
			Category:    "windows_sysmon",
			EventID:     "8",
			Format:      "xml",
			Description: "Remote thread created in another process",
		},
		{
			ID:          "10",
			Name:        "Process Access",
			Category:    "windows_sysmon",
			EventID:     "10",
			Format:      "xml",
			Description: "A process opened another process",
		},
		{
			ID:          "11",
			Name:        "File Create",
			Category:    "windows_sysmon",
			EventID:     "11",
			Format:      "xml",
			Description: "File creation event",
		},
		{
			ID:          "22",
			Name:        "DNS Query",
			Category:    "windows_sysmon",
			EventID:     "22",
			Format:      "xml",
			Description: "DNS query event with query results",
		},
	}
}

// SysmonEvent represents a Sysmon event structure
type SysmonEvent struct {
	XMLName   xml.Name `xml:"Event"`
	Xmlns     string   `xml:"xmlns,attr"`
	System    SysmonEventSystem
	EventData SysmonEventData
}

type SysmonEventSystem struct {
	XMLName       xml.Name `xml:"System"`
	Provider      SysmonEventProvider
	EventID       int    `xml:"EventID"`
	Version       int    `xml:"Version"`
	Level         int    `xml:"Level"`
	Task          int    `xml:"Task"`
	Opcode        int    `xml:"Opcode"`
	Keywords      string `xml:"Keywords"`
	TimeCreated   SysmonTimeCreated
	EventRecordID int64  `xml:"EventRecordID"`
	Correlation   string `xml:"Correlation"`
	Execution     SysmonExecution
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
	Security      SysmonSecurity
}

type SysmonEventProvider struct {
	XMLName string `xml:"Provider"`
	Name    string `xml:"Name,attr"`
	Guid    string `xml:"Guid,attr"`
}

type SysmonTimeCreated struct {
	XMLName    string `xml:"TimeCreated"`
	SystemTime string `xml:"SystemTime,attr"`
}

type SysmonExecution struct {
	XMLName   string `xml:"Execution"`
	ProcessID int    `xml:"ProcessID,attr"`
	ThreadID  int    `xml:"ThreadID,attr"`
}

type SysmonSecurity struct {
	XMLName string `xml:"Security"`
	UserID  string `xml:"UserID,attr,omitempty"`
}

type SysmonEventData struct {
	XMLName xml.Name `xml:"EventData"`
	Data    []SysmonDataItem
}

type SysmonDataItem struct {
	XMLName xml.Name `xml:"Data"`
	Name    string   `xml:"Name,attr"`
	Value   string   `xml:",chardata"`
}

// Generate creates a Sysmon event
func (g *WindowsSysmonGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "1":
		return g.generateEvent1(overrides)
	case "3":
		return g.generateEvent3(overrides)
	case "7":
		return g.generateEvent7(overrides)
	case "8":
		return g.generateEvent8(overrides)
	case "10":
		return g.generateEvent10(overrides)
	case "11":
		return g.generateEvent11(overrides)
	case "22":
		return g.generateEvent22(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// RandomHash generates a random hash
func (g *WindowsSysmonGenerator) RandomHash() string {
	return fmt.Sprintf("SHA256=%s", strings.ToUpper(g.RandomString(64)))
}

// generateEvent1 creates a process creation event
func (g *WindowsSysmonGenerator) generateEvent1(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	processName := g.RandomProcessName()
	processPath := fmt.Sprintf("C:\\Windows\\System32\\%s", processName)

	fields := map[string]interface{}{
		"RuleName":            "-",
		"UtcTime":             now.Format("2006-01-02 15:04:05.000"),
		"ProcessGuid":         fmt.Sprintf("{%s}", g.RandomGUID()),
		"ProcessId":           g.RandomInt(1000, 65535),
		"Image":               processPath,
		"FileVersion":         "10.0.19041.1 (WinBuild.160101.0800)",
		"Description":         "Windows Process",
		"Product":             "Microsoft Windows Operating System",
		"Company":             "Microsoft Corporation",
		"OriginalFileName":    processName,
		"CommandLine":         processPath,
		"CurrentDirectory":    "C:\\Windows\\System32\\",
		"User":                fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
		"LogonGuid":           fmt.Sprintf("{%s}", g.RandomGUID()),
		"LogonId":             fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"TerminalSessionId":   g.RandomInt(0, 5),
		"IntegrityLevel":      g.RandomChoice([]string{"Low", "Medium", "High", "System"}),
		"Hashes":              g.RandomHash(),
		"ParentProcessGuid":   fmt.Sprintf("{%s}", g.RandomGUID()),
		"ParentProcessId":     g.RandomInt(1000, 65535),
		"ParentImage":         "C:\\Windows\\System32\\services.exe",
		"ParentCommandLine":   "C:\\Windows\\system32\\services.exe",
		"ParentUser":          "NT AUTHORITY\\SYSTEM",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(1, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_sysmon",
		EventID:    "1",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
	}, nil
}

// generateEvent3 creates a network connection event
func (g *WindowsSysmonGenerator) generateEvent3(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	protocols := []string{"tcp", "udp"}
	initiated := g.RandomInt(0, 1) == 1

	fields := map[string]interface{}{
		"RuleName":           "-",
		"UtcTime":            now.Format("2006-01-02 15:04:05.000"),
		"ProcessGuid":        fmt.Sprintf("{%s}", g.RandomGUID()),
		"ProcessId":          g.RandomInt(1000, 65535),
		"Image":              g.RandomPath(),
		"User":               fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
		"Protocol":           g.RandomChoice(protocols),
		"Initiated":          initiated,
		"SourceIsIpv6":       false,
		"SourceIp":           g.RandomIPv4Internal(),
		"SourceHostname":     g.RandomHostname(),
		"SourcePort":         g.RandomPort(),
		"SourcePortName":     "-",
		"DestinationIsIpv6":  false,
		"DestinationIp":      g.RandomIPv4External(),
		"DestinationHostname": "-",
		"DestinationPort":    g.RandomCommonPort(),
		"DestinationPortName": "-",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(3, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_sysmon",
		EventID:    "3",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
	}, nil
}

// generateEvent7 creates an image loaded event
func (g *WindowsSysmonGenerator) generateEvent7(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	dlls := []string{
		"ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll",
		"ws2_32.dll", "ole32.dll", "oleaut32.dll", "shell32.dll",
	}

	dllName := g.RandomChoice(dlls)
	fields := map[string]interface{}{
		"RuleName":         "-",
		"UtcTime":          now.Format("2006-01-02 15:04:05.000"),
		"ProcessGuid":      fmt.Sprintf("{%s}", g.RandomGUID()),
		"ProcessId":        g.RandomInt(1000, 65535),
		"Image":            g.RandomPath(),
		"ImageLoaded":      fmt.Sprintf("C:\\Windows\\System32\\%s", dllName),
		"FileVersion":      "10.0.19041.1",
		"Description":      "Windows DLL",
		"Product":          "Microsoft Windows Operating System",
		"Company":          "Microsoft Corporation",
		"OriginalFileName": dllName,
		"Hashes":           g.RandomHash(),
		"Signed":           "true",
		"Signature":        "Microsoft Windows",
		"SignatureStatus":  "Valid",
		"User":             fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(7, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_sysmon",
		EventID:    "7",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
	}, nil
}

// generateEvent8 creates a CreateRemoteThread event
func (g *WindowsSysmonGenerator) generateEvent8(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	fields := map[string]interface{}{
		"RuleName":          "-",
		"UtcTime":           now.Format("2006-01-02 15:04:05.000"),
		"SourceProcessGuid": fmt.Sprintf("{%s}", g.RandomGUID()),
		"SourceProcessId":   g.RandomInt(1000, 65535),
		"SourceImage":       g.RandomPath(),
		"TargetProcessGuid": fmt.Sprintf("{%s}", g.RandomGUID()),
		"TargetProcessId":   g.RandomInt(1000, 65535),
		"TargetImage":       g.RandomPath(),
		"NewThreadId":       g.RandomInt(1000, 65535),
		"StartAddress":      fmt.Sprintf("0x%016X", g.RandomInt(0x10000000, 0x7FFFFFFF)),
		"StartModule":       "-",
		"StartFunction":     "-",
		"SourceUser":        fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
		"TargetUser":        fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(8, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_sysmon",
		EventID:    "8",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
	}, nil
}

// generateEvent10 creates a process access event
func (g *WindowsSysmonGenerator) generateEvent10(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	accessMasks := []string{"0x1000", "0x0400", "0x0010", "0x1410", "0x1FFFFF"}

	fields := map[string]interface{}{
		"RuleName":          "-",
		"UtcTime":           now.Format("2006-01-02 15:04:05.000"),
		"SourceProcessGuid": fmt.Sprintf("{%s}", g.RandomGUID()),
		"SourceProcessId":   g.RandomInt(1000, 65535),
		"SourceThreadId":    g.RandomInt(1000, 65535),
		"SourceImage":       g.RandomPath(),
		"TargetProcessGuid": fmt.Sprintf("{%s}", g.RandomGUID()),
		"TargetProcessId":   g.RandomInt(1000, 65535),
		"TargetImage":       "C:\\Windows\\System32\\lsass.exe",
		"GrantedAccess":     g.RandomChoice(accessMasks),
		"CallTrace":         "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4",
		"SourceUser":        fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
		"TargetUser":        "NT AUTHORITY\\SYSTEM",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(10, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_sysmon",
		EventID:    "10",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
	}, nil
}

// generateEvent11 creates a file create event
func (g *WindowsSysmonGenerator) generateEvent11(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	extensions := []string{".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".txt", ".log"}

	fields := map[string]interface{}{
		"RuleName":          "-",
		"UtcTime":           now.Format("2006-01-02 15:04:05.000"),
		"ProcessGuid":       fmt.Sprintf("{%s}", g.RandomGUID()),
		"ProcessId":         g.RandomInt(1000, 65535),
		"Image":             g.RandomPath(),
		"TargetFilename":    fmt.Sprintf("C:\\Users\\%s\\AppData\\Local\\Temp\\%s%s", g.RandomUsername(), g.RandomString(8), g.RandomChoice(extensions)),
		"CreationUtcTime":   now.Format("2006-01-02 15:04:05.000"),
		"User":              fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(11, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_sysmon",
		EventID:    "11",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
	}, nil
}

// generateEvent22 creates a DNS query event
func (g *WindowsSysmonGenerator) generateEvent22(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domains := []string{
		"www.google.com", "api.microsoft.com", "update.microsoft.com",
		"cdn.cloudflare.com", "github.com", "amazonaws.com",
		"login.microsoftonline.com", "outlook.office365.com",
	}
	queryTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT"}
	queryStatuses := []string{"SUCCESS", "NXDOMAIN", "SERVFAIL"}

	queryName := g.RandomChoice(domains)
	fields := map[string]interface{}{
		"RuleName":    "-",
		"UtcTime":     now.Format("2006-01-02 15:04:05.000"),
		"ProcessGuid": fmt.Sprintf("{%s}", g.RandomGUID()),
		"ProcessId":   g.RandomInt(1000, 65535),
		"QueryName":   queryName,
		"QueryType":   g.RandomChoice(queryTypes),
		"QueryStatus": g.RandomChoice(queryStatuses),
		"QueryResults": fmt.Sprintf("type:  5 %s;::ffff:%s;", queryName, g.RandomIPv4External()),
		"Image":       g.RandomPath(),
		"User":        fmt.Sprintf("%s\\%s", g.RandomDomain(), g.RandomUsername()),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildEvent(22, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "windows_sysmon",
		EventID:    "22",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
	}, nil
}

// buildEvent creates the common Sysmon Event structure
func (g *WindowsSysmonGenerator) buildEvent(eventID int, timestamp time.Time, fields map[string]interface{}) SysmonEvent {
	dataItems := make([]SysmonDataItem, 0)
	for name, value := range fields {
		dataItems = append(dataItems, SysmonDataItem{
			Name:  name,
			Value: fmt.Sprintf("%v", value),
		})
	}

	return SysmonEvent{
		Xmlns: "http://schemas.microsoft.com/win/2004/08/events/event",
		System: SysmonEventSystem{
			Provider: SysmonEventProvider{
				Name: "Microsoft-Windows-Sysmon",
				Guid: "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
			},
			EventID:       eventID,
			Version:       5,
			Level:         4,
			Task:          eventID,
			Opcode:        0,
			Keywords:      "0x8000000000000000",
			TimeCreated:   SysmonTimeCreated{SystemTime: timestamp.Format("2006-01-02T15:04:05.000000000Z")},
			EventRecordID: int64(g.RandomInt(100000, 99999999)),
			Execution:     SysmonExecution{ProcessID: g.RandomInt(1000, 5000), ThreadID: g.RandomInt(100, 10000)},
			Channel:       "Microsoft-Windows-Sysmon/Operational",
			Computer:      g.RandomFQDN(),
		},
		EventData: SysmonEventData{Data: dataItems},
	}
}
