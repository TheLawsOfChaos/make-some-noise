package generators

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// AWSALBGenerator generates AWS Application Load Balancer access log events
type AWSALBGenerator struct {
	BaseGenerator
}

func init() {
	Register(&AWSALBGenerator{})
}

// GetEventType returns the event type for AWS ALB Access Logs
func (g *AWSALBGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "aws_alb",
		Name:        "AWS ALB Access Logs",
		Category:    "web",
		Description: "AWS Application Load Balancer request logs",
		EventIDs:    []string{"http", "https", "h2", "ws", "wss"},
	}
}

// GetTemplates returns available templates for AWS ALB events
func (g *AWSALBGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "http_success",
			Name:        "HTTP Success",
			Category:    "aws_alb",
			EventID:     "http",
			Format:      "text",
			Description: "Successful HTTP request through ALB",
		},
		{
			ID:          "https_success",
			Name:        "HTTPS Success",
			Category:    "aws_alb",
			EventID:     "https",
			Format:      "text",
			Description: "Successful HTTPS request through ALB",
		},
		{
			ID:          "target_error",
			Name:        "Target Error",
			Category:    "aws_alb",
			EventID:     "https",
			Format:      "text",
			Description: "Target returned 5xx error",
		},
		{
			ID:          "elb_error",
			Name:        "ELB Error",
			Category:    "aws_alb",
			EventID:     "https",
			Format:      "text",
			Description: "ALB returned error (502/503/504)",
		},
		{
			ID:          "slow_response",
			Name:        "Slow Response",
			Category:    "aws_alb",
			EventID:     "https",
			Format:      "text",
			Description: "Request with high latency",
		},
		{
			ID:          "websocket",
			Name:        "WebSocket Connection",
			Category:    "aws_alb",
			EventID:     "wss",
			Format:      "text",
			Description: "WebSocket connection through ALB",
		},
	}
}

// Generate creates an AWS ALB access log event
func (g *AWSALBGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "http_success":
		return g.generateALBLog("http", 200, 200, false, overrides)
	case "https_success":
		return g.generateALBLog("https", 200, 200, false, overrides)
	case "target_error":
		return g.generateALBLog("https", 502, 500, false, overrides)
	case "elb_error":
		return g.generateALBLog("https", 503, -1, false, overrides)
	case "slow_response":
		return g.generateALBLog("https", 200, 200, true, overrides)
	case "websocket":
		return g.generateALBLog("wss", 101, 101, false, overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *AWSALBGenerator) randomALBName() string {
	names := []string{"app", "api", "web", "internal", "public"}
	return fmt.Sprintf("%s-alb-%s", g.RandomChoice(names), g.RandomString(8))
}

func (g *AWSALBGenerator) randomTargetGroup() string {
	names := []string{"web-targets", "api-targets", "backend-targets", "app-targets"}
	return fmt.Sprintf("targetgroup/%s/%s", g.RandomChoice(names), g.RandomString(16))
}

func (g *AWSALBGenerator) randomRegion() string {
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
	return g.RandomChoice(regions)
}

func (g *AWSALBGenerator) randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
		"curl/7.88.1",
		"Amazon CloudFront",
		"ELB-HealthChecker/2.0",
	}
	return g.RandomChoice(agents)
}

func (g *AWSALBGenerator) generateALBLog(requestType string, elbStatusCode, targetStatusCode int, slowResponse bool, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()

	albName := g.randomALBName()
	region := g.randomRegion()
	clientIP := g.RandomIPv4External()
	clientPort := g.RandomPort()
	targetIP := g.RandomIPv4Internal()
	targetPort := g.RandomChoice([]string{"80", "8080", "3000", "5000"})

	var requestProcessingTime, targetProcessingTime, responseProcessingTime float64
	if slowResponse {
		requestProcessingTime = float64(g.RandomInt(1, 10)) / 1000
		targetProcessingTime = float64(g.RandomInt(5000, 30000)) / 1000
		responseProcessingTime = float64(g.RandomInt(1, 100)) / 1000
	} else {
		requestProcessingTime = float64(g.RandomInt(1, 10)) / 1000
		targetProcessingTime = float64(g.RandomInt(10, 500)) / 1000
		responseProcessingTime = float64(g.RandomInt(1, 50)) / 1000
	}

	receivedBytes := g.RandomInt(100, 10000)
	sentBytes := g.RandomInt(1000, 100000)

	methods := []string{"GET", "GET", "GET", "POST", "PUT", "DELETE"}
	method := g.RandomChoice(methods)
	paths := []string{"/", "/api/v1/users", "/api/v1/health", "/login", "/static/app.js", "/images/logo.png"}
	path := g.RandomChoice(paths)

	targetGroupArn := fmt.Sprintf("arn:aws:elasticloadbalancing:%s:123456789012:%s", region, g.randomTargetGroup())

	userAgent := g.randomUserAgent()
	sslCipher := g.RandomChoice([]string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "-"})
	sslProtocol := g.RandomChoice([]string{"TLSv1.2", "TLSv1.3", "-"})

	traceID := fmt.Sprintf("Root=1-%x-%s", timestamp.Unix(), g.RandomString(24))

	// Target status code of -1 means target didn't respond
	targetStatusStr := "-"
	targetStr := "-"
	if targetStatusCode > 0 {
		targetStatusStr = fmt.Sprintf("%d", targetStatusCode)
		targetStr = fmt.Sprintf("%s:%s", targetIP, targetPort)
	}

	// ALB log format (simplified)
	rawEvent := fmt.Sprintf("%s %s %s/%s:%d %s:%d %s %.3f %.3f %.3f %d %s %d %d \"%s %s://%s%s HTTP/1.1\" \"%s\" %s %s %s \"%s\" \"%s\" \"%s\" %s",
		requestType,
		timestamp.Format("2006-01-02T15:04:05.000000Z"),
		fmt.Sprintf("app/%s/%s", albName, g.RandomString(16)),
		clientIP,
		clientPort,
		targetStr,
		targetPort,
		requestProcessingTime,
		targetProcessingTime,
		responseProcessingTime,
		elbStatusCode,
		targetStatusStr,
		receivedBytes,
		sentBytes,
		method,
		requestType,
		fmt.Sprintf("%s.%s.elb.amazonaws.com", albName, region),
		path,
		userAgent,
		sslCipher,
		sslProtocol,
		targetGroupArn,
		traceID,
		"-",
		"-",
		"0",
	)

	fields := map[string]interface{}{
		"type":                      requestType,
		"timestamp":                 timestamp.Format(time.RFC3339),
		"elb":                       albName,
		"client_ip":                 clientIP,
		"client_port":               clientPort,
		"target_ip":                 targetIP,
		"target_port":               targetPort,
		"request_processing_time":   requestProcessingTime,
		"target_processing_time":    targetProcessingTime,
		"response_processing_time":  responseProcessingTime,
		"elb_status_code":           elbStatusCode,
		"target_status_code":        targetStatusCode,
		"received_bytes":            receivedBytes,
		"sent_bytes":                sentBytes,
		"request_method":            method,
		"request_url":               path,
		"user_agent":                userAgent,
		"ssl_cipher":                sslCipher,
		"ssl_protocol":              sslProtocol,
		"target_group_arn":          targetGroupArn,
		"trace_id":                  traceID,
		"region":                    region,
	}

	fields = g.ApplyOverrides(fields, overrides)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_alb",
		EventID:    requestType,
		Timestamp:  timestamp,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "aws:elb:accesslogs",
	}, nil
}
