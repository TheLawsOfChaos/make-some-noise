package generators

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// WebServerGenerator generates Apache/Nginx access log events
type WebServerGenerator struct {
	BaseGenerator
}

func init() {
	Register(&WebServerGenerator{})
}

// GetEventType returns the event type for Web Server Access Logs
func (g *WebServerGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "webserver",
		Name:        "Apache/Nginx Access Logs",
		Category:    "web",
		Description: "Web server access logs in combined format",
		EventIDs:    []string{"200", "301", "302", "400", "401", "403", "404", "500"},
	}
}

// GetTemplates returns available templates for Web Server events
func (g *WebServerGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "success",
			Name:        "Successful Request",
			Category:    "webserver",
			EventID:     "200",
			Format:      "text",
			Description: "HTTP 200 OK response",
		},
		{
			ID:          "redirect",
			Name:        "Redirect",
			Category:    "webserver",
			EventID:     "302",
			Format:      "text",
			Description: "HTTP 301/302 redirect",
		},
		{
			ID:          "not_found",
			Name:        "Not Found",
			Category:    "webserver",
			EventID:     "404",
			Format:      "text",
			Description: "HTTP 404 not found",
		},
		{
			ID:          "unauthorized",
			Name:        "Unauthorized",
			Category:    "webserver",
			EventID:     "401",
			Format:      "text",
			Description: "HTTP 401 unauthorized",
		},
		{
			ID:          "forbidden",
			Name:        "Forbidden",
			Category:    "webserver",
			EventID:     "403",
			Format:      "text",
			Description: "HTTP 403 forbidden",
		},
		{
			ID:          "server_error",
			Name:        "Server Error",
			Category:    "webserver",
			EventID:     "500",
			Format:      "text",
			Description: "HTTP 500 internal server error",
		},
	}
}

// Generate creates a Web Server access log event
func (g *WebServerGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "success":
		return g.generateAccess(200, overrides)
	case "redirect":
		return g.generateAccess(g.RandomChoice([]string{"301", "302"}), overrides)
	case "not_found":
		return g.generateAccess(404, overrides)
	case "unauthorized":
		return g.generateAccess(401, overrides)
	case "forbidden":
		return g.generateAccess(403, overrides)
	case "server_error":
		return g.generateAccess(500, overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *WebServerGenerator) randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"curl/7.88.1",
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
	}
	return g.RandomChoice(agents)
}

func (g *WebServerGenerator) randomURI() string {
	uris := []string{
		"/", "/index.html", "/about", "/contact", "/login", "/api/v1/users",
		"/api/v1/products", "/static/js/app.js", "/static/css/style.css",
		"/images/logo.png", "/admin", "/dashboard", "/api/health",
		"/wp-admin", "/phpmyadmin", "/.env", "/config.php",
	}
	return g.RandomChoice(uris)
}

func (g *WebServerGenerator) randomMethod() string {
	methods := []string{"GET", "GET", "GET", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
	return g.RandomChoice(methods)
}

func (g *WebServerGenerator) randomReferer() string {
	referers := []string{
		"-",
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://example.com/",
		"https://internal.company.com/dashboard",
	}
	return g.RandomChoice(referers)
}

func (g *WebServerGenerator) generateAccess(statusCode interface{}, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()

	var code int
	switch v := statusCode.(type) {
	case int:
		code = v
	case string:
		fmt.Sscanf(v, "%d", &code)
	}

	clientIP := g.RandomIPv4External()
	method := g.randomMethod()
	uri := g.randomURI()
	protocol := "HTTP/1.1"
	bytesSent := g.RandomInt(100, 100000)
	userAgent := g.randomUserAgent()
	referer := g.randomReferer()
	responseTime := float64(g.RandomInt(1, 5000)) / 1000 // seconds

	// Combined Log Format
	rawEvent := fmt.Sprintf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"",
		clientIP,
		timestamp.Format("02/Jan/2006:15:04:05 -0700"),
		method,
		uri,
		protocol,
		code,
		bytesSent,
		referer,
		userAgent,
	)

	fields := map[string]interface{}{
		"client_ip":     clientIP,
		"ident":         "-",
		"auth_user":     "-",
		"timestamp":     timestamp.Format(time.RFC3339),
		"method":        method,
		"uri":           uri,
		"protocol":      protocol,
		"status_code":   code,
		"bytes_sent":    bytesSent,
		"referer":       referer,
		"user_agent":    userAgent,
		"response_time": responseTime,
	}

	fields = g.ApplyOverrides(fields, overrides)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "webserver",
		EventID:    fmt.Sprintf("%d", code),
		Timestamp:  timestamp,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "access_combined",
	}, nil
}
