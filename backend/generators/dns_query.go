package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// DNSQueryGenerator generates DNS query log events
type DNSQueryGenerator struct {
	BaseGenerator
}

func init() {
	Register(&DNSQueryGenerator{})
}

// GetEventType returns the event type for DNS Query Logs
func (g *DNSQueryGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "dns_query",
		Name:        "DNS Query Logs",
		Category:    "network",
		Description: "DNS request/response logs for threat hunting and visibility",
		EventIDs:    []string{"QUERY", "RESPONSE", "NXDOMAIN", "BLOCKED"},
	}
}

// GetTemplates returns available templates for DNS Query Log events
func (g *DNSQueryGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "query_success",
			Name:        "Successful Query",
			Category:    "dns_query",
			EventID:     "RESPONSE",
			Format:      "json",
			Description: "Successful DNS resolution",
		},
		{
			ID:          "query_nxdomain",
			Name:        "NXDOMAIN Response",
			Category:    "dns_query",
			EventID:     "NXDOMAIN",
			Format:      "json",
			Description: "Domain not found response",
		},
		{
			ID:          "query_blocked",
			Name:        "Blocked Query",
			Category:    "dns_query",
			EventID:     "BLOCKED",
			Format:      "json",
			Description: "Query blocked by DNS filtering",
		},
		{
			ID:          "query_suspicious",
			Name:        "Suspicious Domain Query",
			Category:    "dns_query",
			EventID:     "RESPONSE",
			Format:      "json",
			Description: "Query for suspicious/DGA domain",
		},
		{
			ID:          "query_external",
			Name:        "External DNS Query",
			Category:    "dns_query",
			EventID:     "QUERY",
			Format:      "json",
			Description: "Query to external DNS resolver",
		},
		{
			ID:          "query_tunneling",
			Name:        "DNS Tunneling Attempt",
			Category:    "dns_query",
			EventID:     "BLOCKED",
			Format:      "json",
			Description: "Suspected DNS tunneling activity",
		},
	}
}

// Generate creates a DNS Query Log event
func (g *DNSQueryGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "query_success":
		return g.generateQuerySuccess(overrides)
	case "query_nxdomain":
		return g.generateQueryNXDomain(overrides)
	case "query_blocked":
		return g.generateQueryBlocked(overrides)
	case "query_suspicious":
		return g.generateQuerySuspicious(overrides)
	case "query_external":
		return g.generateQueryExternal(overrides)
	case "query_tunneling":
		return g.generateQueryTunneling(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *DNSQueryGenerator) randomDNSServer() string {
	servers := []string{"dns-01.corp.local", "dns-02.corp.local", "pi-hole.home.local", "10.0.0.53", "10.0.1.53"}
	return g.RandomChoice(servers)
}

func (g *DNSQueryGenerator) randomQueryType() string {
	types := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV"}
	return g.RandomChoice(types)
}

func (g *DNSQueryGenerator) randomLegitDomain() string {
	domains := []string{
		"www.google.com", "login.microsoftonline.com", "api.github.com",
		"cdn.cloudflare.com", "s3.amazonaws.com", "update.microsoft.com",
		"www.office.com", "teams.microsoft.com", "zoom.us", "slack.com",
	}
	return g.RandomChoice(domains)
}

func (g *DNSQueryGenerator) randomMaliciousDomain() string {
	// DGA-like domains
	return fmt.Sprintf("%s.%s", g.RandomString(g.RandomInt(8, 20)), g.RandomChoice([]string{"xyz", "top", "tk", "ml", "ga", "cf"}))
}

func (g *DNSQueryGenerator) buildBaseEvent(queryName, queryType, responseCode, action string) map[string]interface{} {
	timestamp := time.Now().UTC()
	return map[string]interface{}{
		"timestamp":       timestamp.Format(time.RFC3339Nano),
		"dns_server":      g.randomDNSServer(),
		"client_ip":       g.RandomIPv4Internal(),
		"client_port":     g.RandomPort(),
		"query_name":      queryName,
		"query_type":      queryType,
		"query_class":     "IN",
		"response_code":   responseCode,
		"response_time_ms": g.RandomInt(1, 200),
		"protocol":        g.RandomChoice([]string{"UDP", "TCP", "DoH", "DoT"}),
		"action":          action,
		"transaction_id":  g.RandomInt(1, 65535),
		"flags": map[string]interface{}{
			"authoritative":     g.RandomInt(0, 1) == 1,
			"truncated":         false,
			"recursion_desired": true,
			"recursion_available": true,
		},
	}
}

func (g *DNSQueryGenerator) generateQuerySuccess(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	domain := g.randomLegitDomain()
	queryType := g.randomQueryType()

	event := g.buildBaseEvent(domain, queryType, "NOERROR", "ALLOW")

	if queryType == "A" {
		event["answers"] = []map[string]interface{}{
			{"type": "A", "data": g.RandomIPv4External(), "ttl": g.RandomInt(60, 86400)},
		}
	} else if queryType == "AAAA" {
		event["answers"] = []map[string]interface{}{
			{"type": "AAAA", "data": fmt.Sprintf("2001:db8::%x:%x", g.RandomInt(0, 65535), g.RandomInt(0, 65535)), "ttl": g.RandomInt(60, 86400)},
		}
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "dns_query",
		EventID:    "RESPONSE",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "dns:query",
	}, nil
}

func (g *DNSQueryGenerator) generateQueryNXDomain(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	// Non-existent domain
	domain := fmt.Sprintf("%s.%s.com", g.RandomString(8), g.RandomString(5))

	event := g.buildBaseEvent(domain, "A", "NXDOMAIN", "ALLOW")
	event["answers"] = []map[string]interface{}{}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "dns_query",
		EventID:    "NXDOMAIN",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "dns:query",
	}, nil
}

func (g *DNSQueryGenerator) generateQueryBlocked(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()

	blockedDomains := []string{
		"malware.evil.com", "tracking.ads.net", "phishing-site.xyz",
		"crypto-miner.io", "botnet-c2.ru", "adult-content.xxx",
	}
	domain := g.RandomChoice(blockedDomains)

	event := g.buildBaseEvent(domain, "A", "REFUSED", "BLOCK")
	event["block_reason"] = g.RandomChoice([]string{"malware", "phishing", "ads", "adult", "policy"})
	event["block_list"] = g.RandomChoice([]string{"threat-intel-feed", "category-block", "custom-blacklist"})

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "dns_query",
		EventID:    "BLOCKED",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "dns:query",
	}, nil
}

func (g *DNSQueryGenerator) generateQuerySuspicious(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	domain := g.randomMaliciousDomain()

	event := g.buildBaseEvent(domain, "A", "NOERROR", "ALLOW")
	event["threat_intel"] = map[string]interface{}{
		"matched":   true,
		"category":  g.RandomChoice([]string{"DGA", "C2", "malware", "phishing"}),
		"confidence": g.RandomInt(60, 100),
		"source":    g.RandomChoice([]string{"internal-ioc", "threat-feed-1", "machine-learning"}),
	}
	event["answers"] = []map[string]interface{}{
		{"type": "A", "data": g.RandomIPv4External(), "ttl": g.RandomInt(60, 3600)},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "dns_query",
		EventID:    "RESPONSE",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "dns:query",
	}, nil
}

func (g *DNSQueryGenerator) generateQueryExternal(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	domain := g.randomLegitDomain()

	event := g.buildBaseEvent(domain, "A", "NOERROR", "ALLOW")
	event["dns_server"] = g.RandomChoice([]string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222"})
	event["policy_violation"] = true
	event["violation_type"] = "external_dns_usage"

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "dns_query",
		EventID:    "QUERY",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "dns:query",
	}, nil
}

func (g *DNSQueryGenerator) generateQueryTunneling(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	// Long subdomain typical of DNS tunneling
	tunnelData := g.RandomString(g.RandomInt(50, 200))
	domain := fmt.Sprintf("%s.tunnel.evil.com", tunnelData)

	event := g.buildBaseEvent(domain, "TXT", "REFUSED", "BLOCK")
	event["block_reason"] = "dns_tunneling"
	event["anomaly_score"] = g.RandomInt(80, 100)
	event["query_length"] = len(domain)
	event["entropy"] = fmt.Sprintf("%.2f", float64(g.RandomInt(35, 45))/10)

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "dns_query",
		EventID:    "BLOCKED",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "dns:query",
	}, nil
}
