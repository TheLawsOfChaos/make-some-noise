package generators

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// MicrosoftADGenerator generates Microsoft Active Directory events
type MicrosoftADGenerator struct {
	BaseGenerator
}

func init() {
	Register(&MicrosoftADGenerator{})
}

// GetEventType returns the event type for Microsoft AD
func (g *MicrosoftADGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "microsoft_ad",
		Name:        "Microsoft Active Directory",
		Category:    "identity",
		Description: "Microsoft Active Directory events for user, group, and object management",
		EventIDs:    []string{"4720", "4722", "4723", "4724", "4725", "4726", "4728", "4729", "4732", "4733", "4740", "4767"},
	}
}

// GetTemplates returns available templates for Microsoft AD events
func (g *MicrosoftADGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "4720",
			Name:        "User Account Created",
			Category:    "microsoft_ad",
			EventID:     "4720",
			Format:      "xml",
			Description: "A user account was created",
		},
		{
			ID:          "4722",
			Name:        "User Account Enabled",
			Category:    "microsoft_ad",
			EventID:     "4722",
			Format:      "xml",
			Description: "A user account was enabled",
		},
		{
			ID:          "4723",
			Name:        "Password Change Attempt",
			Category:    "microsoft_ad",
			EventID:     "4723",
			Format:      "xml",
			Description: "An attempt was made to change an account's password",
		},
		{
			ID:          "4724",
			Name:        "Password Reset",
			Category:    "microsoft_ad",
			EventID:     "4724",
			Format:      "xml",
			Description: "An attempt was made to reset an account's password",
		},
		{
			ID:          "4725",
			Name:        "User Account Disabled",
			Category:    "microsoft_ad",
			EventID:     "4725",
			Format:      "xml",
			Description: "A user account was disabled",
		},
		{
			ID:          "4726",
			Name:        "User Account Deleted",
			Category:    "microsoft_ad",
			EventID:     "4726",
			Format:      "xml",
			Description: "A user account was deleted",
		},
		{
			ID:          "4728",
			Name:        "Member Added to Global Group",
			Category:    "microsoft_ad",
			EventID:     "4728",
			Format:      "xml",
			Description: "A member was added to a security-enabled global group",
		},
		{
			ID:          "4729",
			Name:        "Member Removed from Global Group",
			Category:    "microsoft_ad",
			EventID:     "4729",
			Format:      "xml",
			Description: "A member was removed from a security-enabled global group",
		},
		{
			ID:          "4732",
			Name:        "Member Added to Local Group",
			Category:    "microsoft_ad",
			EventID:     "4732",
			Format:      "xml",
			Description: "A member was added to a security-enabled local group",
		},
		{
			ID:          "4740",
			Name:        "User Account Locked",
			Category:    "microsoft_ad",
			EventID:     "4740",
			Format:      "xml",
			Description: "A user account was locked out",
		},
		{
			ID:          "4767",
			Name:        "User Account Unlocked",
			Category:    "microsoft_ad",
			EventID:     "4767",
			Format:      "xml",
			Description: "A user account was unlocked",
		},
	}
}

// ADEvent represents an AD event structure
type ADEvent struct {
	XMLName   xml.Name `xml:"Event"`
	Xmlns     string   `xml:"xmlns,attr"`
	System    ADEventSystem
	EventData ADEventData
}

type ADEventSystem struct {
	XMLName       xml.Name `xml:"System"`
	Provider      ADEventProvider
	EventID       int    `xml:"EventID"`
	Version       int    `xml:"Version"`
	Level         int    `xml:"Level"`
	Task          int    `xml:"Task"`
	Opcode        int    `xml:"Opcode"`
	Keywords      string `xml:"Keywords"`
	TimeCreated   ADTimeCreated
	EventRecordID int64  `xml:"EventRecordID"`
	Correlation   string `xml:"Correlation"`
	Execution     ADExecution
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
	Security      ADSecurity
}

type ADEventProvider struct {
	XMLName string `xml:"Provider"`
	Name    string `xml:"Name,attr"`
	Guid    string `xml:"Guid,attr"`
}

type ADTimeCreated struct {
	XMLName    string `xml:"TimeCreated"`
	SystemTime string `xml:"SystemTime,attr"`
}

type ADExecution struct {
	XMLName   string `xml:"Execution"`
	ProcessID int    `xml:"ProcessID,attr"`
	ThreadID  int    `xml:"ThreadID,attr"`
}

type ADSecurity struct {
	XMLName string `xml:"Security"`
	UserID  string `xml:"UserID,attr,omitempty"`
}

type ADEventData struct {
	XMLName xml.Name `xml:"EventData"`
	Data    []ADDataItem
}

type ADDataItem struct {
	XMLName xml.Name `xml:"Data"`
	Name    string   `xml:"Name,attr"`
	Value   string   `xml:",chardata"`
}

// Generate creates a Microsoft AD event
func (g *MicrosoftADGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "4720":
		return g.generate4720(overrides)
	case "4722":
		return g.generate4722(overrides)
	case "4723":
		return g.generate4723(overrides)
	case "4724":
		return g.generate4724(overrides)
	case "4725":
		return g.generate4725(overrides)
	case "4726":
		return g.generate4726(overrides)
	case "4728":
		return g.generate4728(overrides)
	case "4729":
		return g.generate4729(overrides)
	case "4732":
		return g.generate4732(overrides)
	case "4740":
		return g.generate4740(overrides)
	case "4767":
		return g.generate4767(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// RandomDCName generates a random domain controller name
func (g *MicrosoftADGenerator) RandomDCName() string {
	sites := []string{"DC1", "DC2", "PDC", "BDC"}
	return fmt.Sprintf("%s.%s.local", g.RandomChoice(sites), g.RandomDomain())
}

// RandomOU generates a random OU path
func (g *MicrosoftADGenerator) RandomOU() string {
	ous := []string{
		"OU=Users,DC=%s,DC=local",
		"OU=Admins,OU=Users,DC=%s,DC=local",
		"OU=Service Accounts,DC=%s,DC=local",
		"OU=Employees,OU=Users,DC=%s,DC=local",
		"OU=Contractors,OU=Users,DC=%s,DC=local",
	}
	return fmt.Sprintf(g.RandomChoice(ous), g.RandomDomain())
}

// RandomGroupName generates a random group name
func (g *MicrosoftADGenerator) RandomGroupName() string {
	groups := []string{
		"Domain Admins",
		"Domain Users",
		"Enterprise Admins",
		"Administrators",
		"Remote Desktop Users",
		"Backup Operators",
		"Server Operators",
		"IT-Admins",
		"Help Desk",
		"Finance-Users",
	}
	return g.RandomChoice(groups)
}

// buildADEvent creates the common AD Event structure
func (g *MicrosoftADGenerator) buildADEvent(eventID int, task int, timestamp time.Time, fields map[string]interface{}) ADEvent {
	dataItems := make([]ADDataItem, 0)
	for name, value := range fields {
		dataItems = append(dataItems, ADDataItem{
			Name:  name,
			Value: fmt.Sprintf("%v", value),
		})
	}

	return ADEvent{
		Xmlns: "http://schemas.microsoft.com/win/2004/08/events/event",
		System: ADEventSystem{
			Provider: ADEventProvider{
				Name: "Microsoft-Windows-Security-Auditing",
				Guid: "{54849625-5478-4994-A5BA-3E3B0328C30D}",
			},
			EventID:       eventID,
			Version:       0,
			Level:         0,
			Task:          task,
			Opcode:        0,
			Keywords:      "0x8020000000000000",
			TimeCreated:   ADTimeCreated{SystemTime: timestamp.Format("2006-01-02T15:04:05.000000000Z")},
			EventRecordID: int64(g.RandomInt(100000, 99999999)),
			Execution:     ADExecution{ProcessID: g.RandomInt(500, 1000), ThreadID: g.RandomInt(100, 10000)},
			Channel:       "Security",
			Computer:      g.RandomDCName(),
		},
		EventData: ADEventData{Data: dataItems},
	}
}

// generate4720 creates a user account created event
func (g *MicrosoftADGenerator) generate4720(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	newUser := g.RandomUsername()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"TargetUserName":    newUser,
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":     "-",
		"SamAccountName":    newUser,
		"DisplayName":       fmt.Sprintf("%s %s", g.RandomString(6), g.RandomString(8)),
		"UserPrincipalName": fmt.Sprintf("%s@%s.local", newUser, domain),
		"HomeDirectory":     "-",
		"HomePath":          "-",
		"ScriptPath":        "-",
		"ProfilePath":       "-",
		"UserWorkstations":  "-",
		"PasswordLastSet":   now.Format("1/2/2006 3:04:05 PM"),
		"AccountExpires":    "%%1794",
		"PrimaryGroupId":    "513",
		"AllowedToDelegateTo": "-",
		"OldUacValue":       "0x0",
		"NewUacValue":       "0x15",
		"UserAccountControl": "%%2080\n\t\t%%2082\n\t\t%%2084",
		"UserParameters":    "-",
		"SidHistory":        "-",
		"LogonHours":        "%%1793",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4720, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4720",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4722 creates a user account enabled event
func (g *MicrosoftADGenerator) generate4722(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"TargetUserName":    g.RandomUsername(),
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4722, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4722",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4723 creates a password change attempt event
func (g *MicrosoftADGenerator) generate4723(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()
	user := g.RandomUsername()

	fields := map[string]interface{}{
		"TargetUserName":    user,
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   user,
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":     "-",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4723, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4723",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4724 creates a password reset event
func (g *MicrosoftADGenerator) generate4724(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"TargetUserName":    g.RandomUsername(),
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4724, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4724",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4725 creates a user account disabled event
func (g *MicrosoftADGenerator) generate4725(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"TargetUserName":    g.RandomUsername(),
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4725, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4725",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4726 creates a user account deleted event
func (g *MicrosoftADGenerator) generate4726(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"TargetUserName":    g.RandomUsername(),
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":     "-",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4726, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4726",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4728 creates a member added to global group event
func (g *MicrosoftADGenerator) generate4728(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"MemberName":        fmt.Sprintf("CN=%s,%s", g.RandomUsername(), g.RandomOU()),
		"MemberSid":         g.RandomSID(),
		"TargetUserName":    g.RandomGroupName(),
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":     "-",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4728, 13826, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4728",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4729 creates a member removed from global group event
func (g *MicrosoftADGenerator) generate4729(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"MemberName":        fmt.Sprintf("CN=%s,%s", g.RandomUsername(), g.RandomOU()),
		"MemberSid":         g.RandomSID(),
		"TargetUserName":    g.RandomGroupName(),
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":     "-",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4729, 13826, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4729",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4732 creates a member added to local group event
func (g *MicrosoftADGenerator) generate4732(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()
	localGroups := []string{"Administrators", "Remote Desktop Users", "Backup Operators", "Power Users"}

	fields := map[string]interface{}{
		"MemberName":        fmt.Sprintf("CN=%s,%s", g.RandomUsername(), g.RandomOU()),
		"MemberSid":         g.RandomSID(),
		"TargetUserName":    g.RandomChoice(localGroups),
		"TargetDomainName":  "Builtin",
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
		"PrivilegeList":     "-",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4732, 13826, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4732",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4740 creates a user account locked event
func (g *MicrosoftADGenerator) generate4740(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"TargetUserName":   g.RandomUsername(),
		"TargetDomainName": domain,
		"TargetSid":        g.RandomSID(),
		"SubjectUserName":  g.RandomDCName(),
		"SubjectDomainName": domain,
		"SubjectLogonId":   "0x0",
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4740, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4740",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}

// generate4767 creates a user account unlocked event
func (g *MicrosoftADGenerator) generate4767(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	domain := g.RandomDomain()

	fields := map[string]interface{}{
		"TargetUserName":    g.RandomUsername(),
		"TargetDomainName":  domain,
		"TargetSid":         g.RandomSID(),
		"SubjectUserSid":    g.RandomSID(),
		"SubjectUserName":   g.RandomUsername(),
		"SubjectDomainName": domain,
		"SubjectLogonId":    fmt.Sprintf("0x%x", g.RandomInt(100000, 9999999)),
	}

	fields = g.ApplyOverrides(fields, overrides)

	event := g.buildADEvent(4767, 13824, now, fields)
	rawEvent, err := xml.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "microsoft_ad",
		EventID:    "4767",
		Timestamp:  now,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "WinEventLog:Security",
	}, nil
}
