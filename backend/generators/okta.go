package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// OktaGenerator generates Okta System Log events
type OktaGenerator struct {
	BaseGenerator
}

func init() {
	Register(&OktaGenerator{})
}

// GetEventType returns the event type for Okta System Logs
func (g *OktaGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "okta",
		Name:        "Okta System Logs",
		Category:    "identity",
		Description: "Okta authentication events, MFA challenges, admin actions, and policy changes",
		EventIDs:    []string{"user.session.start", "user.authentication.sso", "user.mfa.factor.activate", "user.account.lock", "policy.lifecycle.update", "application.lifecycle.create"},
	}
}

// GetTemplates returns available templates for Okta System Log events
func (g *OktaGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "session_start",
			Name:        "Session Start",
			Category:    "okta",
			EventID:     "user.session.start",
			Format:      "json",
			Description: "User session initiated",
		},
		{
			ID:          "sso_auth",
			Name:        "SSO Authentication",
			Category:    "okta",
			EventID:     "user.authentication.sso",
			Format:      "json",
			Description: "SSO authentication to application",
		},
		{
			ID:          "mfa_enroll",
			Name:        "MFA Factor Enrollment",
			Category:    "okta",
			EventID:     "user.mfa.factor.activate",
			Format:      "json",
			Description: "MFA factor enrollment",
		},
		{
			ID:          "account_lock",
			Name:        "Account Locked",
			Category:    "okta",
			EventID:     "user.account.lock",
			Format:      "json",
			Description: "User account locked due to failed attempts",
		},
		{
			ID:          "auth_failure",
			Name:        "Authentication Failure",
			Category:    "okta",
			EventID:     "user.session.start",
			Format:      "json",
			Description: "Failed authentication attempt",
		},
		{
			ID:          "password_reset",
			Name:        "Password Reset",
			Category:    "okta",
			EventID:     "user.account.reset_password",
			Format:      "json",
			Description: "Password reset completed",
		},
	}
}

// Generate creates an Okta System Log event
func (g *OktaGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "session_start":
		return g.generateSessionStart(overrides)
	case "sso_auth":
		return g.generateSSOAuth(overrides)
	case "mfa_enroll":
		return g.generateMFAEnroll(overrides)
	case "account_lock":
		return g.generateAccountLock(overrides)
	case "auth_failure":
		return g.generateAuthFailure(overrides)
	case "password_reset":
		return g.generatePasswordReset(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *OktaGenerator) randomOktaUser() (string, string, string) {
	firstNames := []string{"John", "Jane", "Bob", "Alice", "Charlie", "Diana", "Eve", "Frank"}
	lastNames := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"}
	firstName := g.RandomChoice(firstNames)
	lastName := g.RandomChoice(lastNames)
	email := fmt.Sprintf("%s.%s@company.com", firstName, lastName)
	return firstName, lastName, email
}

func (g *OktaGenerator) randomOktaOrgURL() string {
	orgs := []string{"company", "acme", "contoso", "initech", "umbrella"}
	return fmt.Sprintf("https://%s.okta.com", g.RandomChoice(orgs))
}

func (g *OktaGenerator) randomApplication() (string, string) {
	apps := []struct {
		name  string
		label string
	}{
		{"0oa1234567890abcdef", "Salesforce"},
		{"0oa0987654321fedcba", "AWS Console"},
		{"0oaabc123def456ghi", "Office 365"},
		{"0oaxyz789uvw012rst", "GitHub Enterprise"},
		{"0oalmnop345qrs678tu", "Slack"},
	}
	app := apps[g.RandomInt(0, len(apps)-1)]
	return app.name, app.label
}

func (g *OktaGenerator) buildBaseEvent(eventType, displayMessage, outcome string) map[string]interface{} {
	timestamp := time.Now().UTC()
	firstName, lastName, email := g.randomOktaUser()
	userID := "00u" + g.RandomString(17)

	return map[string]interface{}{
		"uuid":       uuid.New().String(),
		"published":  timestamp.Format(time.RFC3339Nano),
		"eventType":  eventType,
		"version":    "0",
		"severity":   g.RandomChoice([]string{"INFO", "WARN", "ERROR"}),
		"legacyEventType": eventType,
		"displayMessage":  displayMessage,
		"actor": map[string]interface{}{
			"id":          userID,
			"type":        "User",
			"alternateId": email,
			"displayName": fmt.Sprintf("%s %s", firstName, lastName),
		},
		"client": map[string]interface{}{
			"userAgent": map[string]interface{}{
				"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"os":           "Windows 10",
				"browser":      "Chrome",
			},
			"zone":            "null",
			"device":          "Computer",
			"id":              nil,
			"ipAddress":       g.RandomIPv4External(),
			"geographicalContext": map[string]interface{}{
				"city":       g.RandomChoice([]string{"New York", "San Francisco", "Chicago", "Austin", "Seattle"}),
				"state":      g.RandomChoice([]string{"NY", "CA", "IL", "TX", "WA"}),
				"country":    "United States",
				"postalCode": fmt.Sprintf("%05d", g.RandomInt(10000, 99999)),
				"geolocation": map[string]interface{}{
					"lat": fmt.Sprintf("%.4f", float64(g.RandomInt(30, 48))+float64(g.RandomInt(0, 9999))/10000),
					"lon": fmt.Sprintf("-%.4f", float64(g.RandomInt(70, 122))+float64(g.RandomInt(0, 9999))/10000),
				},
			},
		},
		"outcome": map[string]interface{}{
			"result": outcome,
		},
		"target":             []interface{}{},
		"transaction":        map[string]interface{}{"type": "WEB", "id": g.RandomString(20)},
		"debugContext":       map[string]interface{}{},
		"authenticationContext": map[string]interface{}{
			"authenticationStep": 0,
			"externalSessionId":  g.RandomString(32),
		},
		"securityContext": map[string]interface{}{
			"asNumber": g.RandomInt(1000, 65000),
			"asOrg":    g.RandomChoice([]string{"Comcast", "AT&T", "Verizon", "Google Cloud"}),
			"isp":      g.RandomChoice([]string{"Comcast", "AT&T", "Verizon", "Google Cloud"}),
			"domain":   g.RandomChoice([]string{"comcast.net", "att.net", "verizon.net", "googlecloud.com"}),
		},
		"request": map[string]interface{}{
			"ipChain": []map[string]interface{}{
				{"ip": g.RandomIPv4External()},
			},
		},
	}
}

func (g *OktaGenerator) generateSessionStart(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("user.session.start", "User login to Okta", "SUCCESS")

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "okta",
		EventID:    "user.session.start",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "okta:im",
	}, nil
}

func (g *OktaGenerator) generateSSOAuth(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	appID, appLabel := g.randomApplication()

	event := g.buildBaseEvent("user.authentication.sso", fmt.Sprintf("User single sign on to app: %s", appLabel), "SUCCESS")

	event["target"] = []map[string]interface{}{
		{
			"id":          appID,
			"type":        "AppInstance",
			"alternateId": appLabel,
			"displayName": appLabel,
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "okta",
		EventID:    "user.authentication.sso",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "okta:im",
	}, nil
}

func (g *OktaGenerator) generateMFAEnroll(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	factorType := g.RandomChoice([]string{"token:software:totp", "push", "sms", "email", "webauthn"})

	event := g.buildBaseEvent("user.mfa.factor.activate", fmt.Sprintf("MFA factor activated: %s", factorType), "SUCCESS")

	event["target"] = []map[string]interface{}{
		{
			"id":          "mfa" + g.RandomString(17),
			"type":        "Factor",
			"alternateId": factorType,
			"displayName": factorType,
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "okta",
		EventID:    "user.mfa.factor.activate",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "okta:im",
	}, nil
}

func (g *OktaGenerator) generateAccountLock(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("user.account.lock", "User account locked due to excessive failed login attempts", "SUCCESS")
	event["severity"] = "WARN"

	event["debugContext"] = map[string]interface{}{
		"debugData": map[string]interface{}{
			"lockoutReason": "EXCESSIVE_FAILED_LOGINS",
			"failedAttempts": g.RandomInt(5, 10),
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "okta",
		EventID:    "user.account.lock",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "okta:im",
	}, nil
}

func (g *OktaGenerator) generateAuthFailure(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("user.session.start", "User login to Okta", "FAILURE")
	event["severity"] = "WARN"

	reasons := []string{"INVALID_CREDENTIALS", "LOCKED_OUT", "MFA_ENROLL_REQUIRED", "PASSWORD_EXPIRED"}
	event["outcome"] = map[string]interface{}{
		"result": "FAILURE",
		"reason": g.RandomChoice(reasons),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "okta",
		EventID:    "user.session.start",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "okta:im",
	}, nil
}

func (g *OktaGenerator) generatePasswordReset(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("user.account.reset_password", "User password was reset", "SUCCESS")

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "okta",
		EventID:    "user.account.reset_password",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "okta:im",
	}, nil
}
