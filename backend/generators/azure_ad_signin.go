package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// AzureADSignInGenerator generates Azure AD Sign-in Log events
type AzureADSignInGenerator struct {
	BaseGenerator
}

func init() {
	Register(&AzureADSignInGenerator{})
}

// GetEventType returns the event type for Azure AD Sign-in Logs
func (g *AzureADSignInGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "azure_ad_signin",
		Name:        "Azure AD Sign-in Logs",
		Category:    "identity",
		Description: "Azure/M365 authentication and conditional access events",
		EventIDs:    []string{"SignInSuccess", "SignInFailure", "MFAChallenge", "ConditionalAccessBlock"},
	}
}

// GetTemplates returns available templates for Azure AD Sign-in Log events
func (g *AzureADSignInGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "interactive_success",
			Name:        "Interactive Sign-in Success",
			Category:    "azure_ad_signin",
			EventID:     "SignInSuccess",
			Format:      "json",
			Description: "Successful interactive user sign-in",
		},
		{
			ID:          "interactive_failure",
			Name:        "Interactive Sign-in Failure",
			Category:    "azure_ad_signin",
			EventID:     "SignInFailure",
			Format:      "json",
			Description: "Failed interactive user sign-in",
		},
		{
			ID:          "mfa_challenge",
			Name:        "MFA Challenge",
			Category:    "azure_ad_signin",
			EventID:     "MFAChallenge",
			Format:      "json",
			Description: "MFA challenge during sign-in",
		},
		{
			ID:          "conditional_access_block",
			Name:        "Conditional Access Block",
			Category:    "azure_ad_signin",
			EventID:     "ConditionalAccessBlock",
			Format:      "json",
			Description: "Sign-in blocked by conditional access policy",
		},
		{
			ID:          "risky_signin",
			Name:        "Risky Sign-in",
			Category:    "azure_ad_signin",
			EventID:     "SignInSuccess",
			Format:      "json",
			Description: "Sign-in flagged as risky by Identity Protection",
		},
		{
			ID:          "service_principal",
			Name:        "Service Principal Sign-in",
			Category:    "azure_ad_signin",
			EventID:     "SignInSuccess",
			Format:      "json",
			Description: "Non-interactive service principal sign-in",
		},
	}
}

// Generate creates an Azure AD Sign-in Log event
func (g *AzureADSignInGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "interactive_success":
		return g.generateInteractiveSuccess(overrides)
	case "interactive_failure":
		return g.generateInteractiveFailure(overrides)
	case "mfa_challenge":
		return g.generateMFAChallenge(overrides)
	case "conditional_access_block":
		return g.generateConditionalAccessBlock(overrides)
	case "risky_signin":
		return g.generateRiskySignin(overrides)
	case "service_principal":
		return g.generateServicePrincipal(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *AzureADSignInGenerator) randomTenantID() string {
	return uuid.New().String()
}

func (g *AzureADSignInGenerator) randomUser() (string, string, string) {
	firstNames := []string{"John", "Jane", "Bob", "Alice", "Charlie", "Diana"}
	lastNames := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"}
	firstName := g.RandomChoice(firstNames)
	lastName := g.RandomChoice(lastNames)
	domain := g.RandomChoice([]string{"contoso.com", "fabrikam.com", "company.onmicrosoft.com"})
	return fmt.Sprintf("%s %s", firstName, lastName), fmt.Sprintf("%s.%s@%s", firstName, lastName, domain), uuid.New().String()
}

func (g *AzureADSignInGenerator) randomApplication() (string, string) {
	apps := []struct {
		id   string
		name string
	}{
		{uuid.New().String(), "Microsoft Office 365"},
		{uuid.New().String(), "Microsoft Teams"},
		{uuid.New().String(), "Azure Portal"},
		{uuid.New().String(), "Microsoft Graph"},
		{uuid.New().String(), "SharePoint Online"},
	}
	app := apps[g.RandomInt(0, len(apps)-1)]
	return app.id, app.name
}

func (g *AzureADSignInGenerator) randomDeviceInfo() map[string]interface{} {
	return map[string]interface{}{
		"deviceId":          uuid.New().String(),
		"displayName":       fmt.Sprintf("%s-%s", g.RandomChoice([]string{"LAPTOP", "DESKTOP", "MOBILE"}), g.RandomString(6)),
		"operatingSystem":   g.RandomChoice([]string{"Windows 10", "Windows 11", "macOS", "iOS", "Android"}),
		"browser":           g.RandomChoice([]string{"Chrome 120", "Edge 120", "Safari 17", "Firefox 121"}),
		"isCompliant":       g.RandomInt(0, 1) == 1,
		"isManaged":         g.RandomInt(0, 1) == 1,
		"trustType":         g.RandomChoice([]string{"Azure AD Joined", "Hybrid Azure AD Joined", "Azure AD Registered", ""}),
	}
}

func (g *AzureADSignInGenerator) randomLocation() map[string]interface{} {
	cities := []struct {
		city    string
		state   string
		country string
	}{
		{"New York", "New York", "US"},
		{"Los Angeles", "California", "US"},
		{"London", "", "GB"},
		{"Paris", "", "FR"},
		{"Tokyo", "", "JP"},
	}
	loc := cities[g.RandomInt(0, len(cities)-1)]
	return map[string]interface{}{
		"city":            loc.city,
		"state":           loc.state,
		"countryOrRegion": loc.country,
		"geoCoordinates": map[string]interface{}{
			"latitude":  fmt.Sprintf("%.4f", float64(g.RandomInt(-90, 90))+float64(g.RandomInt(0, 9999))/10000),
			"longitude": fmt.Sprintf("%.4f", float64(g.RandomInt(-180, 180))+float64(g.RandomInt(0, 9999))/10000),
		},
	}
}

func (g *AzureADSignInGenerator) buildBaseEvent() map[string]interface{} {
	timestamp := time.Now().UTC()
	displayName, upn, userID := g.randomUser()
	appID, appName := g.randomApplication()
	tenantID := g.randomTenantID()

	return map[string]interface{}{
		"id":             uuid.New().String(),
		"createdDateTime": timestamp.Format(time.RFC3339),
		"userDisplayName": displayName,
		"userPrincipalName": upn,
		"userId":          userID,
		"appId":           appID,
		"appDisplayName":  appName,
		"ipAddress":       g.RandomIPv4External(),
		"clientAppUsed":   g.RandomChoice([]string{"Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync"}),
		"correlationId":   uuid.New().String(),
		"conditionalAccessStatus": "success",
		"isInteractive":   true,
		"riskDetail":      "none",
		"riskLevelAggregated": "none",
		"riskLevelDuringSignIn": "none",
		"riskState":       "none",
		"resourceDisplayName": appName,
		"resourceId":      appID,
		"status": map[string]interface{}{
			"errorCode":       0,
			"failureReason":   nil,
			"additionalDetails": nil,
		},
		"deviceDetail":    g.randomDeviceInfo(),
		"location":        g.randomLocation(),
		"authenticationDetails": []map[string]interface{}{
			{
				"authenticationMethod":     "Password",
				"authenticationStepDateTime": timestamp.Format(time.RFC3339),
				"succeeded":                true,
			},
		},
		"authenticationRequirement": "singleFactorAuthentication",
		"tenantId":        tenantID,
	}
}

func (g *AzureADSignInGenerator) generateInteractiveSuccess(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_ad_signin",
		EventID:    "SignInSuccess",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:aad:signin",
	}, nil
}

func (g *AzureADSignInGenerator) generateInteractiveFailure(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent()

	errorCodes := []struct {
		code   int
		reason string
	}{
		{50126, "Invalid username or password"},
		{50053, "Account is locked"},
		{50057, "User account is disabled"},
		{50055, "Password is expired"},
		{50074, "Strong authentication is required"},
	}
	errorInfo := errorCodes[g.RandomInt(0, len(errorCodes)-1)]

	event["status"] = map[string]interface{}{
		"errorCode":     errorInfo.code,
		"failureReason": errorInfo.reason,
	}
	event["authenticationDetails"].([]map[string]interface{})[0]["succeeded"] = false

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_ad_signin",
		EventID:    "SignInFailure",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:aad:signin",
	}, nil
}

func (g *AzureADSignInGenerator) generateMFAChallenge(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent()

	event["authenticationRequirement"] = "multiFactorAuthentication"
	event["authenticationDetails"] = []map[string]interface{}{
		{
			"authenticationMethod":     "Password",
			"authenticationStepDateTime": timestamp.Add(-10 * time.Second).Format(time.RFC3339),
			"succeeded":                true,
		},
		{
			"authenticationMethod":     g.RandomChoice([]string{"PhoneAppNotification", "PhoneAppOTP", "Text message", "Microsoft Authenticator App"}),
			"authenticationStepDateTime": timestamp.Format(time.RFC3339),
			"succeeded":                true,
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_ad_signin",
		EventID:    "MFAChallenge",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:aad:signin",
	}, nil
}

func (g *AzureADSignInGenerator) generateConditionalAccessBlock(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent()

	event["conditionalAccessStatus"] = "failure"
	event["status"] = map[string]interface{}{
		"errorCode":     53003,
		"failureReason": "Blocked by Conditional Access",
	}

	policies := []string{"Block legacy authentication", "Require compliant device", "Block risky sign-ins", "Require MFA for admins"}
	event["appliedConditionalAccessPolicies"] = []map[string]interface{}{
		{
			"id":            uuid.New().String(),
			"displayName":   g.RandomChoice(policies),
			"result":        "failure",
			"enforcedGrantControls": []string{"block"},
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_ad_signin",
		EventID:    "ConditionalAccessBlock",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:aad:signin",
	}, nil
}

func (g *AzureADSignInGenerator) generateRiskySignin(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent()

	riskLevels := []string{"low", "medium", "high"}
	riskDetails := []string{"unfamiliarFeatures", "anonymizedIPAddress", "impossibleTravel", "maliciousIPAddress"}

	event["riskDetail"] = g.RandomChoice(riskDetails)
	event["riskLevelAggregated"] = g.RandomChoice(riskLevels)
	event["riskLevelDuringSignIn"] = g.RandomChoice(riskLevels)
	event["riskState"] = "atRisk"

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_ad_signin",
		EventID:    "SignInSuccess",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:aad:signin",
	}, nil
}

func (g *AzureADSignInGenerator) generateServicePrincipal(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent()

	spNames := []string{"Azure DevOps", "Terraform", "GitHub Actions", "Backup Service", "Monitoring Agent"}
	spName := g.RandomChoice(spNames)

	event["userDisplayName"] = spName
	event["userPrincipalName"] = ""
	event["isInteractive"] = false
	event["clientAppUsed"] = "Other clients"
	event["authenticationRequirement"] = "singleFactorAuthentication"
	event["authenticationDetails"] = []map[string]interface{}{
		{
			"authenticationMethod":     "ClientSecret",
			"authenticationStepDateTime": timestamp.Format(time.RFC3339),
			"succeeded":                true,
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_ad_signin",
		EventID:    "SignInSuccess",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:aad:signin",
	}, nil
}
