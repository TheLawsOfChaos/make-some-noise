package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// O365AuditGenerator generates Office 365 audit log events
type O365AuditGenerator struct {
	BaseGenerator
}

func init() {
	Register(&O365AuditGenerator{})
}

// GetEventType returns the event type for O365 Audit Logs
func (g *O365AuditGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "o365_audit",
		Name:        "Office 365 Audit Logs",
		Category:    "cloud",
		Description: "Microsoft 365 user and admin activity (SharePoint, Exchange, Teams, OneDrive)",
		EventIDs:    []string{"FileAccessed", "FileModified", "FileDeleted", "UserLoggedIn", "MailItemsAccessed", "TeamCreated"},
	}
}

// GetTemplates returns available templates for O365 Audit events
func (g *O365AuditGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "file_accessed",
			Name:        "File Accessed",
			Category:    "o365_audit",
			EventID:     "FileAccessed",
			Format:      "json",
			Description: "SharePoint/OneDrive file access",
		},
		{
			ID:          "file_modified",
			Name:        "File Modified",
			Category:    "o365_audit",
			EventID:     "FileModified",
			Format:      "json",
			Description: "SharePoint/OneDrive file modification",
		},
		{
			ID:          "file_deleted",
			Name:        "File Deleted",
			Category:    "o365_audit",
			EventID:     "FileDeleted",
			Format:      "json",
			Description: "SharePoint/OneDrive file deletion",
		},
		{
			ID:          "user_login",
			Name:        "User Login",
			Category:    "o365_audit",
			EventID:     "UserLoggedIn",
			Format:      "json",
			Description: "User sign-in to Office 365",
		},
		{
			ID:          "mail_accessed",
			Name:        "Mail Items Accessed",
			Category:    "o365_audit",
			EventID:     "MailItemsAccessed",
			Format:      "json",
			Description: "Exchange mailbox access",
		},
		{
			ID:          "team_created",
			Name:        "Team Created",
			Category:    "o365_audit",
			EventID:     "TeamCreated",
			Format:      "json",
			Description: "Microsoft Teams team creation",
		},
	}
}

// Generate creates an O365 Audit event
func (g *O365AuditGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "file_accessed":
		return g.generateFileAccessed(overrides)
	case "file_modified":
		return g.generateFileModified(overrides)
	case "file_deleted":
		return g.generateFileDeleted(overrides)
	case "user_login":
		return g.generateUserLogin(overrides)
	case "mail_accessed":
		return g.generateMailAccessed(overrides)
	case "team_created":
		return g.generateTeamCreated(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *O365AuditGenerator) randomTenantID() string {
	return uuid.New().String()
}

func (g *O365AuditGenerator) randomUser() (string, string) {
	firstNames := []string{"John", "Jane", "Bob", "Alice", "Charlie", "Diana"}
	lastNames := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"}
	firstName := g.RandomChoice(firstNames)
	lastName := g.RandomChoice(lastNames)
	domain := g.RandomChoice([]string{"contoso.com", "fabrikam.com", "company.onmicrosoft.com"})
	email := fmt.Sprintf("%s.%s@%s", firstName, lastName, domain)
	return fmt.Sprintf("%s %s", firstName, lastName), email
}

func (g *O365AuditGenerator) randomFilename() string {
	names := []string{"Report", "Budget", "Presentation", "Document", "Spreadsheet", "Plan", "Analysis"}
	extensions := []string{".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".csv"}
	return fmt.Sprintf("%s_%s%s", g.RandomChoice(names), g.RandomString(4), g.RandomChoice(extensions))
}

func (g *O365AuditGenerator) randomSiteUrl() string {
	sites := []string{"sites/marketing", "sites/engineering", "sites/hr", "sites/finance", "personal/john_smith"}
	return fmt.Sprintf("https://contoso.sharepoint.com/%s", g.RandomChoice(sites))
}

func (g *O365AuditGenerator) buildBaseEvent(operation, workload, recordType string) map[string]interface{} {
	timestamp := time.Now().UTC()
	_, userEmail := g.randomUser()

	return map[string]interface{}{
		"CreationTime":        timestamp.Format("2006-01-02T15:04:05"),
		"Id":                  uuid.New().String(),
		"Operation":           operation,
		"OrganizationId":      g.randomTenantID(),
		"RecordType":          recordType,
		"ResultStatus":        "Succeeded",
		"UserKey":             uuid.New().String(),
		"UserType":            0,
		"Version":             1,
		"Workload":            workload,
		"ClientIP":            g.RandomIPv4External(),
		"UserId":              userEmail,
		"UserAgent":           g.RandomChoice([]string{"Mozilla/5.0", "Microsoft Office/16.0", "OneDrive/21.0"}),
	}
}

func (g *O365AuditGenerator) generateFileAccessed(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("FileAccessed", "SharePoint", "6")

	filename := g.randomFilename()
	siteUrl := g.randomSiteUrl()

	event["ObjectId"] = fmt.Sprintf("%s/Shared Documents/%s", siteUrl, filename)
	event["SourceFileName"] = filename
	event["SourceFileExtension"] = filename[len(filename)-5:]
	event["SourceRelativeUrl"] = "Shared Documents"
	event["SiteUrl"] = siteUrl
	event["ItemType"] = "File"
	event["EventSource"] = "SharePoint"

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "o365_audit",
		EventID:    "FileAccessed",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "o365:management:activity",
	}, nil
}

func (g *O365AuditGenerator) generateFileModified(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("FileModified", "SharePoint", "6")

	filename := g.randomFilename()
	siteUrl := g.randomSiteUrl()

	event["ObjectId"] = fmt.Sprintf("%s/Shared Documents/%s", siteUrl, filename)
	event["SourceFileName"] = filename
	event["SiteUrl"] = siteUrl
	event["ItemType"] = "File"
	event["EventSource"] = "SharePoint"
	event["ModifiedProperties"] = []map[string]interface{}{
		{"Name": "ContentModified", "NewValue": timestamp.Format(time.RFC3339)},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "o365_audit",
		EventID:    "FileModified",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "o365:management:activity",
	}, nil
}

func (g *O365AuditGenerator) generateFileDeleted(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("FileDeleted", "SharePoint", "6")

	filename := g.randomFilename()
	siteUrl := g.randomSiteUrl()

	event["ObjectId"] = fmt.Sprintf("%s/Shared Documents/%s", siteUrl, filename)
	event["SourceFileName"] = filename
	event["SiteUrl"] = siteUrl
	event["ItemType"] = "File"
	event["EventSource"] = "SharePoint"

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "o365_audit",
		EventID:    "FileDeleted",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "o365:management:activity",
	}, nil
}

func (g *O365AuditGenerator) generateUserLogin(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("UserLoggedIn", "AzureActiveDirectory", "15")

	apps := []string{"Microsoft 365", "SharePoint Online", "Exchange Online", "Microsoft Teams"}

	event["ApplicationId"] = uuid.New().String()
	event["Application"] = g.RandomChoice(apps)
	event["DeviceProperties"] = []map[string]interface{}{
		{"Name": "OS", "Value": g.RandomChoice([]string{"Windows 10", "Windows 11", "MacOS", "iOS", "Android"})},
		{"Name": "BrowserType", "Value": g.RandomChoice([]string{"Chrome", "Edge", "Safari", "Firefox"})},
	}
	event["ExtendedProperties"] = []map[string]interface{}{
		{"Name": "ResultStatusDetail", "Value": "Success"},
	}
	event["Target"] = []map[string]interface{}{
		{"ID": uuid.New().String(), "Type": 0},
	}
	event["Actor"] = []map[string]interface{}{
		{"ID": event["UserId"], "Type": 0},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "o365_audit",
		EventID:    "UserLoggedIn",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "o365:management:activity",
	}, nil
}

func (g *O365AuditGenerator) generateMailAccessed(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("MailItemsAccessed", "Exchange", "50")

	subjects := []string{
		"Q4 Budget Review", "Meeting Notes", "Project Update",
		"Action Required", "Weekly Report", "Important Information",
	}

	event["MailboxOwnerUPN"] = event["UserId"]
	event["MailboxOwnerSid"] = g.RandomSID()
	event["Folders"] = []map[string]interface{}{
		{"Path": "\\Inbox", "FolderItems": []map[string]interface{}{
			{"InternetMessageId": fmt.Sprintf("<%s@mail.contoso.com>", g.RandomString(32)), "Subject": g.RandomChoice(subjects)},
		}},
	}
	event["OperationProperties"] = []map[string]interface{}{
		{"Name": "MailAccessType", "Value": g.RandomChoice([]string{"Bind", "Sync"})},
	}
	event["SessionId"] = uuid.New().String()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "o365_audit",
		EventID:    "MailItemsAccessed",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "o365:management:activity",
	}, nil
}

func (g *O365AuditGenerator) generateTeamCreated(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("TeamCreated", "MicrosoftTeams", "25")

	teamNames := []string{
		"Project Alpha", "Marketing Team", "Engineering", "Sales Q4",
		"Product Launch", "Customer Success", "IT Support",
	}

	teamName := g.RandomChoice(teamNames)
	event["TeamName"] = teamName
	event["TeamGuid"] = uuid.New().String()
	event["TeamType"] = g.RandomChoice([]string{"Private", "Public"})
	event["Members"] = []map[string]interface{}{
		{"UPN": event["UserId"], "Role": "Owner"},
	}
	event["Settings"] = map[string]interface{}{
		"AllowGiphy":            true,
		"AllowMemberAdd":        true,
		"AllowGuestAccess":      g.RandomInt(0, 1) == 1,
		"AllowChannelCreation":  true,
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "o365_audit",
		EventID:    "TeamCreated",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "o365:management:activity",
	}, nil
}
