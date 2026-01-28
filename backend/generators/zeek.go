package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// ZeekGenerator generates Zeek (Bro) network log events
type ZeekGenerator struct {
	BaseGenerator
}

func init() {
	Register(&ZeekGenerator{})
}

// GetEventType returns the event type for Zeek
func (g *ZeekGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "zeek",
		Name:        "Zeek (Bro) Logs",
		Category:    "network",
		Description: "Zeek network protocol analysis logs (conn, dns, http, ssl, files)",
		EventIDs:    []string{"conn", "dns", "http", "ssl", "files", "notice"},
	}
}

// GetTemplates returns available templates for Zeek events
func (g *ZeekGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "conn",
			Name:        "Connection Log",
			Category:    "zeek",
			EventID:     "conn",
			Format:      "json",
			Description: "Network connection log",
		},
		{
			ID:          "dns",
			Name:        "DNS Log",
			Category:    "zeek",
			EventID:     "dns",
			Format:      "json",
			Description: "DNS query/response log",
		},
		{
			ID:          "http",
			Name:        "HTTP Log",
			Category:    "zeek",
			EventID:     "http",
			Format:      "json",
			Description: "HTTP request/response log",
		},
		{
			ID:          "ssl",
			Name:        "SSL/TLS Log",
			Category:    "zeek",
			EventID:     "ssl",
			Format:      "json",
			Description: "SSL/TLS connection log",
		},
		{
			ID:          "files",
			Name:        "Files Log",
			Category:    "zeek",
			EventID:     "files",
			Format:      "json",
			Description: "File analysis log",
		},
		{
			ID:          "notice",
			Name:        "Notice Log",
			Category:    "zeek",
			EventID:     "notice",
			Format:      "json",
			Description: "Zeek notice/alert log",
		},
	}
}

// Generate creates a Zeek event
func (g *ZeekGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "conn":
		return g.generateConn(overrides)
	case "dns":
		return g.generateDNS(overrides)
	case "http":
		return g.generateHTTP(overrides)
	case "ssl":
		return g.generateSSL(overrides)
	case "files":
		return g.generateFiles(overrides)
	case "notice":
		return g.generateNotice(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *ZeekGenerator) randomUID() string {
	return fmt.Sprintf("C%s", g.RandomString(17))
}

func (g *ZeekGenerator) randomFUID() string {
	return fmt.Sprintf("F%s", g.RandomString(17))
}

func (g *ZeekGenerator) randomService() string {
	services := []string{"http", "ssl", "dns", "ssh", "smtp", "ftp", "irc", "-"}
	return g.RandomChoice(services)
}

func (g *ZeekGenerator) randomConnState() string {
	states := []string{"SF", "S0", "S1", "REJ", "RSTO", "RSTR", "OTH"}
	return g.RandomChoice(states)
}

func (g *ZeekGenerator) generateConn(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	uid := g.randomUID()

	origIP := g.RandomIPv4Internal()
	respIP := g.RandomIPv4External()
	origPort := g.RandomPort()
	respPort := g.RandomCommonPort()
	proto := g.RandomChoice([]string{"tcp", "udp"})
	duration := float64(g.RandomInt(1, 300)) + float64(g.RandomInt(0, 999999))/1000000

	event := map[string]interface{}{
		"ts":          timestamp.Unix(),
		"uid":         uid,
		"id.orig_h":   origIP,
		"id.orig_p":   origPort,
		"id.resp_h":   respIP,
		"id.resp_p":   respPort,
		"proto":       proto,
		"service":     g.randomService(),
		"duration":    duration,
		"orig_bytes":  g.RandomInt(100, 100000),
		"resp_bytes":  g.RandomInt(100, 1000000),
		"conn_state":  g.randomConnState(),
		"local_orig":  true,
		"local_resp":  false,
		"missed_bytes": 0,
		"history":     g.RandomChoice([]string{"ShADadFf", "ShADadfF", "S", "ShR", "ShADadR"}),
		"orig_pkts":   g.RandomInt(1, 100),
		"orig_ip_bytes": g.RandomInt(100, 100000),
		"resp_pkts":   g.RandomInt(1, 200),
		"resp_ip_bytes": g.RandomInt(100, 1000000),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "zeek",
		EventID:    "conn",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "bro:conn:json",
	}, nil
}

func (g *ZeekGenerator) generateDNS(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	uid := g.randomUID()

	domains := []string{
		"www.google.com", "api.microsoft.com", "cdn.cloudflare.com",
		"update.example.com", "login.office365.com", "github.com",
		"api.stripe.com", "s3.amazonaws.com",
	}
	qtype := g.RandomChoice([]string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"})

	event := map[string]interface{}{
		"ts":        timestamp.Unix(),
		"uid":       uid,
		"id.orig_h": g.RandomIPv4Internal(),
		"id.orig_p": g.RandomPort(),
		"id.resp_h": g.RandomChoice([]string{"8.8.8.8", "1.1.1.1", "208.67.222.222"}),
		"id.resp_p": 53,
		"proto":     "udp",
		"trans_id":  g.RandomInt(1, 65535),
		"rtt":       float64(g.RandomInt(1, 100)) / 1000,
		"query":     g.RandomChoice(domains),
		"qclass":    1,
		"qclass_name": "C_INTERNET",
		"qtype":     qtype,
		"qtype_name": qtype,
		"rcode":     0,
		"rcode_name": "NOERROR",
		"AA":        false,
		"TC":        false,
		"RD":        true,
		"RA":        true,
		"Z":         0,
		"answers":   []string{g.RandomIPv4External()},
		"TTLs":      []int{g.RandomInt(60, 86400)},
		"rejected":  false,
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "zeek",
		EventID:    "dns",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "bro:dns:json",
	}, nil
}

func (g *ZeekGenerator) generateHTTP(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	uid := g.randomUID()

	hosts := []string{"www.example.com", "api.service.com", "cdn.website.net", "login.app.io"}
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
	uris := []string{"/", "/api/v1/users", "/login", "/api/data", "/static/js/app.js", "/images/logo.png"}
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		"curl/7.79.1",
		"python-requests/2.28.0",
	}
	statusCodes := []int{200, 201, 204, 301, 302, 400, 401, 403, 404, 500}

	event := map[string]interface{}{
		"ts":               timestamp.Unix(),
		"uid":              uid,
		"id.orig_h":        g.RandomIPv4Internal(),
		"id.orig_p":        g.RandomPort(),
		"id.resp_h":        g.RandomIPv4External(),
		"id.resp_p":        g.RandomChoice([]string{"80", "443", "8080", "8443"}),
		"trans_depth":      1,
		"method":           g.RandomChoice(methods),
		"host":             g.RandomChoice(hosts),
		"uri":              g.RandomChoice(uris),
		"referrer":         "-",
		"version":          "1.1",
		"user_agent":       g.RandomChoice(userAgents),
		"origin":           "-",
		"request_body_len": g.RandomInt(0, 10000),
		"response_body_len": g.RandomInt(0, 100000),
		"status_code":      statusCodes[g.RandomInt(0, len(statusCodes)-1)],
		"status_msg":       "OK",
		"info_code":        "-",
		"info_msg":         "-",
		"tags":             []string{},
		"resp_fuids":       []string{g.randomFUID()},
		"resp_mime_types":  []string{g.RandomChoice([]string{"text/html", "application/json", "text/javascript", "image/png"})},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "zeek",
		EventID:    "http",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "bro:http:json",
	}, nil
}

func (g *ZeekGenerator) generateSSL(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	uid := g.randomUID()

	serverNames := []string{"www.google.com", "api.microsoft.com", "github.com", "aws.amazon.com", "login.salesforce.com"}
	versions := []string{"TLSv12", "TLSv13"}
	ciphers := []string{
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}

	event := map[string]interface{}{
		"ts":             timestamp.Unix(),
		"uid":            uid,
		"id.orig_h":      g.RandomIPv4Internal(),
		"id.orig_p":      g.RandomPort(),
		"id.resp_h":      g.RandomIPv4External(),
		"id.resp_p":      443,
		"version":        g.RandomChoice(versions),
		"cipher":         g.RandomChoice(ciphers),
		"curve":          g.RandomChoice([]string{"x25519", "secp256r1", "secp384r1"}),
		"server_name":    g.RandomChoice(serverNames),
		"resumed":        g.RandomInt(0, 1) == 1,
		"established":    true,
		"cert_chain_fuids": []string{g.randomFUID()},
		"client_cert_chain_fuids": []string{},
		"subject":        fmt.Sprintf("CN=%s,O=Example Corp,L=San Francisco,ST=California,C=US", g.RandomChoice(serverNames)),
		"issuer":         "CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
		"validation_status": "ok",
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "zeek",
		EventID:    "ssl",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "bro:ssl:json",
	}, nil
}

func (g *ZeekGenerator) generateFiles(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	fuid := g.randomFUID()

	mimeTypes := []string{
		"application/x-dosexec", "application/pdf", "application/zip",
		"text/html", "image/png", "application/javascript",
	}
	filenames := []string{"update.exe", "document.pdf", "archive.zip", "invoice.docx", "image.png", "script.js"}

	event := map[string]interface{}{
		"ts":          timestamp.Unix(),
		"fuid":        fuid,
		"tx_hosts":    []string{g.RandomIPv4External()},
		"rx_hosts":    []string{g.RandomIPv4Internal()},
		"conn_uids":   []string{g.randomUID()},
		"source":      g.RandomChoice([]string{"HTTP", "FTP", "SMTP", "SMB"}),
		"depth":       0,
		"analyzers":   []string{g.RandomChoice([]string{"SHA256", "MD5", "PE", "EXTRACT"})},
		"mime_type":   g.RandomChoice(mimeTypes),
		"filename":    g.RandomChoice(filenames),
		"duration":    float64(g.RandomInt(1, 60)),
		"local_orig":  false,
		"is_orig":     false,
		"seen_bytes":  g.RandomInt(1000, 10000000),
		"total_bytes": g.RandomInt(1000, 10000000),
		"missing_bytes": 0,
		"overflow_bytes": 0,
		"timedout":    false,
		"sha256":      g.RandomString(64),
		"md5":         g.RandomString(32),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "zeek",
		EventID:    "files",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "bro:files:json",
	}, nil
}

func (g *ZeekGenerator) generateNotice(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	uid := g.randomUID()

	notices := []struct {
		note string
		msg  string
	}{
		{"SSL::Invalid_Server_Cert", "SSL certificate validation failed"},
		{"Scan::Port_Scan", "Port scan detected from source"},
		{"HTTP::Malicious_User_Agent", "Suspicious user agent detected"},
		{"Intel::Notice", "Indicator match found in traffic"},
		{"Weird::Activity", "Unusual protocol behavior detected"},
		{"DNS::Tunneling", "Possible DNS tunneling detected"},
	}
	notice := notices[g.RandomInt(0, len(notices)-1)]

	event := map[string]interface{}{
		"ts":        timestamp.Unix(),
		"uid":       uid,
		"id.orig_h": g.RandomIPv4External(),
		"id.orig_p": g.RandomPort(),
		"id.resp_h": g.RandomIPv4Internal(),
		"id.resp_p": g.RandomCommonPort(),
		"fuid":      "-",
		"file_mime_type": "-",
		"file_desc": "-",
		"proto":     "tcp",
		"note":      notice.note,
		"msg":       notice.msg,
		"sub":       "",
		"src":       g.RandomIPv4External(),
		"dst":       g.RandomIPv4Internal(),
		"p":         g.RandomCommonPort(),
		"n":         "-",
		"peer_descr": "bro",
		"actions":   []string{g.RandomChoice([]string{"Notice::ACTION_LOG", "Notice::ACTION_ALARM", "Notice::ACTION_EMAIL"})},
		"suppress_for": 3600,
		"dropped":   false,
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "zeek",
		EventID:    "notice",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "bro:notice:json",
	}, nil
}
