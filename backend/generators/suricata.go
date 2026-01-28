package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// SuricataGenerator generates Suricata IDS/IPS events in EVE JSON format
type SuricataGenerator struct {
	BaseGenerator
}

func init() {
	Register(&SuricataGenerator{})
}

// GetEventType returns the event type for Suricata
func (g *SuricataGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "suricata",
		Name:        "Suricata IDS",
		Category:    "network",
		Description: "Suricata IDS/IPS EVE JSON format events including alerts, flows, and DNS",
		EventIDs:    []string{"alert", "flow", "dns", "http", "tls", "fileinfo"},
	}
}

// GetTemplates returns available templates for Suricata events
func (g *SuricataGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "alert",
			Name:        "Alert Event",
			Category:    "suricata",
			EventID:     "alert",
			Format:      "json",
			Description: "Suricata IDS alert event in EVE JSON format",
		},
		{
			ID:          "flow",
			Name:        "Flow Event",
			Category:    "suricata",
			EventID:     "flow",
			Format:      "json",
			Description: "Network flow record",
		},
		{
			ID:          "dns",
			Name:        "DNS Event",
			Category:    "suricata",
			EventID:     "dns",
			Format:      "json",
			Description: "DNS query and response event",
		},
		{
			ID:          "http",
			Name:        "HTTP Event",
			Category:    "suricata",
			EventID:     "http",
			Format:      "json",
			Description: "HTTP request and response event",
		},
		{
			ID:          "tls",
			Name:        "TLS Event",
			Category:    "suricata",
			EventID:     "tls",
			Format:      "json",
			Description: "TLS handshake and certificate event",
		},
		{
			ID:          "fileinfo",
			Name:        "File Info Event",
			Category:    "suricata",
			EventID:     "fileinfo",
			Format:      "json",
			Description: "File extraction and analysis event",
		},
	}
}

// Generate creates a Suricata event
func (g *SuricataGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "alert":
		return g.generateAlert(overrides)
	case "flow":
		return g.generateFlow(overrides)
	case "dns":
		return g.generateDNS(overrides)
	case "http":
		return g.generateHTTP(overrides)
	case "tls":
		return g.generateTLS(overrides)
	case "fileinfo":
		return g.generateFileInfo(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// RandomSuricataSignature returns a random signature message
func (g *SuricataGenerator) RandomSuricataSignature() (int, string, string) {
	signatures := []struct {
		sid      int
		msg      string
		category string
	}{
		{2100498, "GPL ATTACK_RESPONSE id check returned root", "Potentially Bad Traffic"},
		{2013028, "ET POLICY curl User-Agent Outbound", "Potential Corporate Privacy Violation"},
		{2027757, "ET TROJAN CoinMiner Known Malicious Stratum Authline", "A Network Trojan was Detected"},
		{2024792, "ET MALWARE Win32/Emotet CnC Activity", "A Network Trojan was Detected"},
		{2025019, "ET MALWARE Cobalt Strike Beacon Detected", "A Network Trojan was Detected"},
		{2210054, "SURICATA STREAM Packet with broken ack", "Generic Protocol Command Decode"},
		{2019876, "ET SCAN Potential SSH Scan", "Attempted Information Leak"},
		{2008578, "ET SCAN Nmap Scripting Engine User-Agent Detected", "Attempted Information Leak"},
		{2016149, "ET INFO EXE Download Request With Unusual Agent", "Potentially Bad Traffic"},
		{2103141, "GPL DNS SPOOF query response with TTL of 1 min. and target host", "Potentially Bad Traffic"},
	}
	sig := signatures[g.RandomInt(0, len(signatures)-1)]
	return sig.sid, sig.msg, sig.category
}

// generateAlert creates a Suricata alert event
func (g *SuricataGenerator) generateAlert(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	sid, msg, category := g.RandomSuricataSignature()

	fields := map[string]interface{}{
		"timestamp": now.Format("2006-01-02T15:04:05.000000-0700"),
		"flow_id":   g.RandomInt(1000000000000, 9999999999999),
		"in_iface":  fmt.Sprintf("eth%d", g.RandomInt(0, 3)),
		"event_type": "alert",
		"src_ip":    g.RandomIPv4External(),
		"src_port":  g.RandomPort(),
		"dest_ip":   g.RandomIPv4Internal(),
		"dest_port": g.RandomCommonPort(),
		"proto":     g.RandomChoice([]string{"TCP", "UDP"}),
		"alert": map[string]interface{}{
			"action":      g.RandomChoice([]string{"allowed", "blocked"}),
			"gid":         1,
			"signature_id": sid,
			"rev":         g.RandomInt(1, 10),
			"signature":   msg,
			"category":    category,
			"severity":    g.RandomInt(1, 3),
		},
		"app_proto": g.RandomChoice([]string{"http", "tls", "dns", "ssh", "smtp", "ftp", "smb"}),
		"flow": map[string]interface{}{
			"pkts_toserver":  g.RandomInt(1, 1000),
			"pkts_toclient":  g.RandomInt(1, 1000),
			"bytes_toserver": g.RandomInt(100, 1000000),
			"bytes_toclient": g.RandomInt(100, 1000000),
			"start":          now.Add(-time.Duration(g.RandomInt(1, 3600)) * time.Second).Format("2006-01-02T15:04:05.000000-0700"),
		},
		"host": g.RandomHostname(),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "suricata",
		EventID:    "alert",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "suricata",
	}, nil
}

// generateFlow creates a Suricata flow event
func (g *SuricataGenerator) generateFlow(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	startTime := now.Add(-time.Duration(g.RandomInt(1, 3600)) * time.Second)

	fields := map[string]interface{}{
		"timestamp":  now.Format("2006-01-02T15:04:05.000000-0700"),
		"flow_id":    g.RandomInt(1000000000000, 9999999999999),
		"in_iface":   fmt.Sprintf("eth%d", g.RandomInt(0, 3)),
		"event_type": "flow",
		"src_ip":     g.RandomIPv4Internal(),
		"src_port":   g.RandomPort(),
		"dest_ip":    g.RandomIPv4External(),
		"dest_port":  g.RandomCommonPort(),
		"proto":      g.RandomChoice([]string{"TCP", "UDP"}),
		"app_proto":  g.RandomChoice([]string{"http", "tls", "dns", "ssh", "failed"}),
		"flow": map[string]interface{}{
			"pkts_toserver":  g.RandomInt(1, 10000),
			"pkts_toclient":  g.RandomInt(1, 10000),
			"bytes_toserver": g.RandomInt(100, 100000000),
			"bytes_toclient": g.RandomInt(100, 100000000),
			"start":          startTime.Format("2006-01-02T15:04:05.000000-0700"),
			"end":            now.Format("2006-01-02T15:04:05.000000-0700"),
			"age":            int(now.Sub(startTime).Seconds()),
			"state":          g.RandomChoice([]string{"new", "established", "closed"}),
			"reason":         g.RandomChoice([]string{"timeout", "forced", "shutdown"}),
			"alerted":        g.RandomInt(0, 1) == 1,
		},
		"tcp": map[string]interface{}{
			"tcp_flags":    g.RandomChoice([]string{"1f", "1b", "12", "18", "10"}),
			"tcp_flags_ts": g.RandomChoice([]string{"1f", "1b", "12", "18", "10"}),
			"tcp_flags_tc": g.RandomChoice([]string{"1f", "1b", "12", "18", "10"}),
			"syn":          true,
			"fin":          g.RandomInt(0, 1) == 1,
			"rst":          g.RandomInt(0, 1) == 1,
			"psh":          g.RandomInt(0, 1) == 1,
			"ack":          true,
			"state":        g.RandomChoice([]string{"established", "closed", "syn_sent", "syn_recv"}),
		},
		"host": g.RandomHostname(),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "suricata",
		EventID:    "flow",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "suricata",
	}, nil
}

// generateDNS creates a Suricata DNS event
func (g *SuricataGenerator) generateDNS(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	domains := []string{
		"www.google.com", "api.microsoft.com", "cdn.cloudflare.com",
		"github.com", "aws.amazon.com", "login.microsoftonline.com",
		"update.googleapis.com", "api.twitter.com",
	}

	rrTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SOA"}
	rcodes := []string{"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}

	queryDomain := g.RandomChoice(domains)
	rrType := g.RandomChoice(rrTypes)

	fields := map[string]interface{}{
		"timestamp":  now.Format("2006-01-02T15:04:05.000000-0700"),
		"flow_id":    g.RandomInt(1000000000000, 9999999999999),
		"in_iface":   fmt.Sprintf("eth%d", g.RandomInt(0, 3)),
		"event_type": "dns",
		"src_ip":     g.RandomIPv4Internal(),
		"src_port":   g.RandomPort(),
		"dest_ip":    g.RandomChoice([]string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"}),
		"dest_port":  53,
		"proto":      "UDP",
		"dns": map[string]interface{}{
			"type":   g.RandomChoice([]string{"query", "answer"}),
			"id":     g.RandomInt(1, 65535),
			"flags":  "8180",
			"qr":     true,
			"rd":     true,
			"ra":     true,
			"rrname": queryDomain,
			"rrtype": rrType,
			"rcode":  g.RandomChoice(rcodes),
			"ttl":    g.RandomInt(60, 86400),
			"rdata":  g.RandomIPv4External(),
		},
		"host": g.RandomHostname(),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "suricata",
		EventID:    "dns",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "suricata",
	}, nil
}

// generateHTTP creates a Suricata HTTP event
func (g *SuricataGenerator) generateHTTP(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"curl/7.68.0",
		"python-requests/2.25.1",
		"Wget/1.21",
	}
	contentTypes := []string{"text/html", "application/json", "text/plain", "application/xml"}
	statusCodes := []int{200, 201, 301, 302, 400, 401, 403, 404, 500}

	hostname := fmt.Sprintf("www.%s.com", g.RandomString(8))

	fields := map[string]interface{}{
		"timestamp":  now.Format("2006-01-02T15:04:05.000000-0700"),
		"flow_id":    g.RandomInt(1000000000000, 9999999999999),
		"in_iface":   fmt.Sprintf("eth%d", g.RandomInt(0, 3)),
		"event_type": "http",
		"src_ip":     g.RandomIPv4Internal(),
		"src_port":   g.RandomPort(),
		"dest_ip":    g.RandomIPv4External(),
		"dest_port":  g.RandomChoiceInterface([]interface{}{80, 443, 8080, 8443}),
		"proto":      "TCP",
		"tx_id":      g.RandomInt(0, 10),
		"http": map[string]interface{}{
			"hostname":             hostname,
			"url":                  fmt.Sprintf("/%s/%s", g.RandomString(8), g.RandomString(12)),
			"http_user_agent":      g.RandomChoice(userAgents),
			"http_content_type":    g.RandomChoice(contentTypes),
			"http_method":          g.RandomChoice(methods),
			"protocol":             "HTTP/1.1",
			"status":               statusCodes[g.RandomInt(0, len(statusCodes)-1)],
			"length":               g.RandomInt(100, 100000),
			"http_refer":           fmt.Sprintf("https://%s/", hostname),
			"redirect":             "",
		},
		"host": g.RandomHostname(),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "suricata",
		EventID:    "http",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "suricata",
	}, nil
}

// generateTLS creates a Suricata TLS event
func (g *SuricataGenerator) generateTLS(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	versions := []string{"TLS 1.2", "TLS 1.3", "TLSv1.2", "TLSv1.3"}
	organizations := []string{
		"DigiCert Inc", "Let's Encrypt", "Comodo CA Limited",
		"GlobalSign", "Amazon", "Google Trust Services LLC",
	}

	sni := fmt.Sprintf("www.%s.com", g.RandomString(8))
	notBefore := now.Add(-time.Duration(g.RandomInt(30, 365)) * 24 * time.Hour)
	notAfter := now.Add(time.Duration(g.RandomInt(30, 365)) * 24 * time.Hour)

	fields := map[string]interface{}{
		"timestamp":  now.Format("2006-01-02T15:04:05.000000-0700"),
		"flow_id":    g.RandomInt(1000000000000, 9999999999999),
		"in_iface":   fmt.Sprintf("eth%d", g.RandomInt(0, 3)),
		"event_type": "tls",
		"src_ip":     g.RandomIPv4Internal(),
		"src_port":   g.RandomPort(),
		"dest_ip":    g.RandomIPv4External(),
		"dest_port":  443,
		"proto":      "TCP",
		"tls": map[string]interface{}{
			"subject":     fmt.Sprintf("CN=%s", sni),
			"issuerdn":    fmt.Sprintf("CN=%s, O=%s", g.RandomChoice([]string{"R3", "E1", "DigiCert SHA2"}), g.RandomChoice(organizations)),
			"serial":      fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", g.RandomInt(0, 255), g.RandomInt(0, 255), g.RandomInt(0, 255), g.RandomInt(0, 255), g.RandomInt(0, 255), g.RandomInt(0, 255), g.RandomInt(0, 255), g.RandomInt(0, 255)),
			"fingerprint": g.RandomString(40),
			"sni":         sni,
			"version":     g.RandomChoice(versions),
			"notbefore":   notBefore.Format("2006-01-02T15:04:05"),
			"notafter":    notAfter.Format("2006-01-02T15:04:05"),
			"ja3": map[string]interface{}{
				"hash":   g.RandomString(32),
				"string": "771,4865-4866-4867-49195,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
			},
			"ja3s": map[string]interface{}{
				"hash":   g.RandomString(32),
				"string": "771,4865,43-51",
			},
		},
		"host": g.RandomHostname(),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "suricata",
		EventID:    "tls",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "suricata",
	}, nil
}

// generateFileInfo creates a Suricata file info event
func (g *SuricataGenerator) generateFileInfo(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()

	filenames := []string{
		"document.pdf", "report.docx", "image.png", "script.js",
		"archive.zip", "setup.exe", "data.json", "config.xml",
	}

	magics := []string{
		"PDF document",
		"Microsoft Word 2007+",
		"PNG image data",
		"JavaScript source",
		"Zip archive data",
		"PE32 executable",
		"JSON data",
		"XML document",
	}

	fields := map[string]interface{}{
		"timestamp":  now.Format("2006-01-02T15:04:05.000000-0700"),
		"flow_id":    g.RandomInt(1000000000000, 9999999999999),
		"in_iface":   fmt.Sprintf("eth%d", g.RandomInt(0, 3)),
		"event_type": "fileinfo",
		"src_ip":     g.RandomIPv4External(),
		"src_port":   g.RandomCommonPort(),
		"dest_ip":    g.RandomIPv4Internal(),
		"dest_port":  g.RandomPort(),
		"proto":      "TCP",
		"app_proto":  g.RandomChoice([]string{"http", "smtp", "ftp", "smb"}),
		"fileinfo": map[string]interface{}{
			"filename": g.RandomChoice(filenames),
			"magic":    g.RandomChoice(magics),
			"gaps":     false,
			"state":    "CLOSED",
			"md5":      g.RandomString(32),
			"sha1":     g.RandomString(40),
			"sha256":   g.RandomString(64),
			"stored":   g.RandomInt(0, 1) == 1,
			"file_id":  g.RandomInt(1, 1000),
			"size":     g.RandomInt(100, 10000000),
			"tx_id":    g.RandomInt(0, 10),
		},
		"host": g.RandomHostname(),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "suricata",
		EventID:    "fileinfo",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "suricata",
	}, nil
}
