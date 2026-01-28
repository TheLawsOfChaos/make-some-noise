package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// AWSGuardDutyGenerator generates AWS GuardDuty findings
type AWSGuardDutyGenerator struct {
	BaseGenerator
}

func init() {
	Register(&AWSGuardDutyGenerator{})
}

// GetEventType returns the event type for AWS GuardDuty
func (g *AWSGuardDutyGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "aws_guardduty",
		Name:        "AWS GuardDuty",
		Category:    "cloud",
		Description: "AWS GuardDuty threat detection findings - malicious IPs, compromised instances, anomalous behavior",
		EventIDs:    []string{"UnauthorizedAccess:EC2/SSHBruteForce", "Recon:EC2/PortProbeUnprotectedPort", "CryptoCurrency:EC2/BitcoinTool", "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", "Trojan:EC2/BlackholeTraffic", "Backdoor:EC2/C2Activity"},
	}
}

// GetTemplates returns available templates for AWS GuardDuty findings
func (g *AWSGuardDutyGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "SSHBruteForce",
			Name:        "SSH Brute Force",
			Category:    "aws_guardduty",
			EventID:     "UnauthorizedAccess:EC2/SSHBruteForce",
			Format:      "json",
			Description: "EC2 instance is under SSH brute force attack",
		},
		{
			ID:          "PortProbe",
			Name:        "Port Probe",
			Category:    "aws_guardduty",
			EventID:     "Recon:EC2/PortProbeUnprotectedPort",
			Format:      "json",
			Description: "EC2 instance has unprotected port being probed",
		},
		{
			ID:          "CryptoMining",
			Name:        "Crypto Mining",
			Category:    "aws_guardduty",
			EventID:     "CryptoCurrency:EC2/BitcoinTool",
			Format:      "json",
			Description: "EC2 instance is communicating with cryptocurrency mining pool",
		},
		{
			ID:          "ConsoleLoginAnomaly",
			Name:        "Console Login Anomaly",
			Category:    "aws_guardduty",
			EventID:     "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
			Format:      "json",
			Description: "Anomalous console login from unusual location",
		},
		{
			ID:          "BlackholeTraffic",
			Name:        "Blackhole Traffic",
			Category:    "aws_guardduty",
			EventID:     "Trojan:EC2/BlackholeTraffic",
			Format:      "json",
			Description: "EC2 instance is sending traffic to known malicious IP",
		},
		{
			ID:          "C2Activity",
			Name:        "C2 Activity",
			Category:    "aws_guardduty",
			EventID:     "Backdoor:EC2/C2Activity",
			Format:      "json",
			Description: "EC2 instance is communicating with command and control server",
		},
	}
}

// Generate creates an AWS GuardDuty finding
func (g *AWSGuardDutyGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "SSHBruteForce":
		return g.generateSSHBruteForce(overrides)
	case "PortProbe":
		return g.generatePortProbe(overrides)
	case "CryptoMining":
		return g.generateCryptoMining(overrides)
	case "ConsoleLoginAnomaly":
		return g.generateConsoleLoginAnomaly(overrides)
	case "BlackholeTraffic":
		return g.generateBlackholeTraffic(overrides)
	case "C2Activity":
		return g.generateC2Activity(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *AWSGuardDutyGenerator) randomAccountID() string {
	return fmt.Sprintf("%012d", g.RandomInt(100000000000, 999999999999))
}

func (g *AWSGuardDutyGenerator) randomRegion() string {
	regions := []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1"}
	return g.RandomChoice(regions)
}

func (g *AWSGuardDutyGenerator) randomSeverity() (float64, string) {
	severities := []struct {
		value float64
		label string
	}{
		{2.0, "LOW"},
		{4.5, "MEDIUM"},
		{7.0, "HIGH"},
		{8.5, "HIGH"},
	}
	s := severities[g.RandomInt(0, len(severities)-1)]
	return s.value, s.label
}

func (g *AWSGuardDutyGenerator) buildBaseFinding(findingType, title, description, accountID, region string) map[string]interface{} {
	severity, severityLabel := g.randomSeverity()
	return map[string]interface{}{
		"schemaVersion": "2.0",
		"accountId":     accountID,
		"region":        region,
		"partition":     "aws",
		"id":            uuid.New().String(),
		"arn":           fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/%s/finding/%s", region, accountID, g.RandomString(32), uuid.New().String()),
		"type":          findingType,
		"resource":      map[string]interface{}{},
		"service": map[string]interface{}{
			"serviceName":  "guardduty",
			"detectorId":   g.RandomString(32),
			"action":       map[string]interface{}{},
			"resourceRole": "TARGET",
			"additionalInfo": map[string]interface{}{
				"threatListName": g.RandomChoice([]string{"ProofPoint", "CrowdStrike", "ThreatIntelligence"}),
			},
			"eventFirstSeen": time.Now().Add(-time.Duration(g.RandomInt(1, 24)) * time.Hour).UTC().Format(time.RFC3339),
			"eventLastSeen":  time.Now().UTC().Format(time.RFC3339),
			"archived":       false,
			"count":          g.RandomInt(1, 100),
		},
		"severity":    severity,
		"createdAt":   time.Now().UTC().Format(time.RFC3339),
		"updatedAt":   time.Now().UTC().Format(time.RFC3339),
		"title":       title,
		"description": description,
		"confidence":  g.RandomInt(60, 99),
		"severityLabel": severityLabel,
	}
}

func (g *AWSGuardDutyGenerator) generateSSHBruteForce(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	instanceID := fmt.Sprintf("i-%s", g.RandomString(17))

	finding := g.buildBaseFinding(
		"UnauthorizedAccess:EC2/SSHBruteForce",
		fmt.Sprintf("%s is performing SSH brute force attacks against %s", g.RandomIPv4External(), instanceID),
		"EC2 instance is being targeted by SSH brute force attack",
		accountID, region,
	)

	finding["resource"] = map[string]interface{}{
		"resourceType": "Instance",
		"instanceDetails": map[string]interface{}{
			"instanceId":       instanceID,
			"instanceType":     g.RandomChoice([]string{"t3.micro", "t3.small", "m5.large"}),
			"launchTime":       time.Now().Add(-time.Duration(g.RandomInt(1, 30)*24) * time.Hour).UTC().Format(time.RFC3339),
			"platform":         "linux",
			"networkInterfaces": []map[string]interface{}{
				{
					"privateIpAddress": g.RandomIPv4Internal(),
					"publicIp":         g.RandomIPv4External(),
				},
			},
		},
	}

	finding["service"].(map[string]interface{})["action"] = map[string]interface{}{
		"actionType": "NETWORK_CONNECTION",
		"networkConnectionAction": map[string]interface{}{
			"connectionDirection": "INBOUND",
			"remoteIpDetails": map[string]interface{}{
				"ipAddressV4": g.RandomIPv4External(),
				"country":     map[string]interface{}{"countryName": g.RandomChoice([]string{"Russia", "China", "North Korea", "Iran"})},
			},
			"localPortDetails": map[string]interface{}{
				"port":     22,
				"portName": "SSH",
			},
			"protocol": "TCP",
			"blocked":  false,
		},
	}

	fields := g.ApplyOverrides(finding, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_guardduty",
		EventID:    "UnauthorizedAccess:EC2/SSHBruteForce",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:guardduty",
	}, nil
}

func (g *AWSGuardDutyGenerator) generatePortProbe(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	instanceID := fmt.Sprintf("i-%s", g.RandomString(17))

	finding := g.buildBaseFinding(
		"Recon:EC2/PortProbeUnprotectedPort",
		fmt.Sprintf("Unprotected port on EC2 instance %s is being probed", instanceID),
		"EC2 instance has an unprotected port which is being probed by a known malicious host",
		accountID, region,
	)

	port := g.RandomChoice([]string{"3389", "22", "3306", "5432", "27017"})
	finding["resource"] = map[string]interface{}{
		"resourceType": "Instance",
		"instanceDetails": map[string]interface{}{
			"instanceId":   instanceID,
			"instanceType": g.RandomChoice([]string{"t3.micro", "t3.small", "m5.large"}),
		},
	}

	finding["service"].(map[string]interface{})["action"] = map[string]interface{}{
		"actionType": "PORT_PROBE",
		"portProbeAction": map[string]interface{}{
			"portProbeDetails": []map[string]interface{}{
				{
					"localPortDetails": map[string]interface{}{
						"port":     port,
						"portName": g.RandomChoice([]string{"RDP", "SSH", "MySQL", "PostgreSQL", "MongoDB"}),
					},
					"remoteIpDetails": map[string]interface{}{
						"ipAddressV4": g.RandomIPv4External(),
						"country":     map[string]interface{}{"countryName": g.RandomChoice([]string{"Russia", "China", "Unknown"})},
					},
				},
			},
			"blocked": false,
		},
	}

	fields := g.ApplyOverrides(finding, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_guardduty",
		EventID:    "Recon:EC2/PortProbeUnprotectedPort",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:guardduty",
	}, nil
}

func (g *AWSGuardDutyGenerator) generateCryptoMining(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	instanceID := fmt.Sprintf("i-%s", g.RandomString(17))

	finding := g.buildBaseFinding(
		"CryptoCurrency:EC2/BitcoinTool.B!DNS",
		fmt.Sprintf("EC2 instance %s is querying a domain name associated with Bitcoin-related activity", instanceID),
		"EC2 instance is communicating with cryptocurrency mining pool",
		accountID, region,
	)

	finding["resource"] = map[string]interface{}{
		"resourceType": "Instance",
		"instanceDetails": map[string]interface{}{
			"instanceId":   instanceID,
			"instanceType": g.RandomChoice([]string{"c5.xlarge", "c5.2xlarge", "p3.2xlarge"}),
		},
	}

	pools := []string{"pool.minergate.com", "xmr.pool.minergate.com", "stratum.slushpool.com", "eth.2miners.com"}
	finding["service"].(map[string]interface{})["action"] = map[string]interface{}{
		"actionType": "DNS_REQUEST",
		"dnsRequestAction": map[string]interface{}{
			"domain":   g.RandomChoice(pools),
			"protocol": "UDP",
			"blocked":  false,
		},
	}

	fields := g.ApplyOverrides(finding, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_guardduty",
		EventID:    "CryptoCurrency:EC2/BitcoinTool",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:guardduty",
	}, nil
}

func (g *AWSGuardDutyGenerator) generateConsoleLoginAnomaly(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	userName := g.RandomChoice([]string{"admin", "developer", "devops"}) + "-" + g.RandomString(4)

	finding := g.buildBaseFinding(
		"UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
		fmt.Sprintf("Anomalous console login by %s", userName),
		"AWS console was successfully logged into from an unusual location",
		accountID, region,
	)

	finding["resource"] = map[string]interface{}{
		"resourceType": "AccessKey",
		"accessKeyDetails": map[string]interface{}{
			"accessKeyId": "AKIA" + g.RandomString(16),
			"principalId": g.RandomString(21),
			"userType":    "IAMUser",
			"userName":    userName,
		},
	}

	countries := []string{"Russia", "China", "North Korea", "Iran", "Nigeria", "Romania"}
	finding["service"].(map[string]interface{})["action"] = map[string]interface{}{
		"actionType": "AWS_API_CALL",
		"awsApiCallAction": map[string]interface{}{
			"api":         "ConsoleLogin",
			"serviceName": "signin.amazonaws.com",
			"callerType":  "Remote IP",
			"remoteIpDetails": map[string]interface{}{
				"ipAddressV4": g.RandomIPv4External(),
				"country":     map[string]interface{}{"countryName": g.RandomChoice(countries)},
				"city":        map[string]interface{}{"cityName": "Unknown"},
			},
		},
	}

	fields := g.ApplyOverrides(finding, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_guardduty",
		EventID:    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:guardduty",
	}, nil
}

func (g *AWSGuardDutyGenerator) generateBlackholeTraffic(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	instanceID := fmt.Sprintf("i-%s", g.RandomString(17))

	finding := g.buildBaseFinding(
		"Trojan:EC2/BlackholeTraffic",
		fmt.Sprintf("EC2 instance %s is attempting to communicate with an IP address that is a known black hole", instanceID),
		"EC2 instance is sending traffic to known malicious IP",
		accountID, region,
	)

	finding["resource"] = map[string]interface{}{
		"resourceType": "Instance",
		"instanceDetails": map[string]interface{}{
			"instanceId":   instanceID,
			"instanceType": g.RandomChoice([]string{"t3.micro", "t3.small", "m5.large"}),
		},
	}

	finding["service"].(map[string]interface{})["action"] = map[string]interface{}{
		"actionType": "NETWORK_CONNECTION",
		"networkConnectionAction": map[string]interface{}{
			"connectionDirection": "OUTBOUND",
			"remoteIpDetails": map[string]interface{}{
				"ipAddressV4":  g.RandomIPv4External(),
				"organization": map[string]interface{}{"asn": "AS12345", "asnOrg": "MaliciousHosting"},
			},
			"localPortDetails":  map[string]interface{}{"port": g.RandomPort()},
			"remotePortDetails": map[string]interface{}{"port": 443},
			"protocol":          "TCP",
			"blocked":           false,
		},
	}

	fields := g.ApplyOverrides(finding, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_guardduty",
		EventID:    "Trojan:EC2/BlackholeTraffic",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:guardduty",
	}, nil
}

func (g *AWSGuardDutyGenerator) generateC2Activity(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	instanceID := fmt.Sprintf("i-%s", g.RandomString(17))

	finding := g.buildBaseFinding(
		"Backdoor:EC2/C2Activity.B!DNS",
		fmt.Sprintf("EC2 instance %s is querying a domain name associated with a known C2 server", instanceID),
		"EC2 instance is communicating with command and control server",
		accountID, region,
	)

	finding["resource"] = map[string]interface{}{
		"resourceType": "Instance",
		"instanceDetails": map[string]interface{}{
			"instanceId":   instanceID,
			"instanceType": g.RandomChoice([]string{"t3.micro", "t3.small", "m5.large"}),
		},
	}

	c2Domains := []string{"malware-c2.evil.com", "command.badactor.net", "control.threat.io", "beacon.apt.org"}
	finding["service"].(map[string]interface{})["action"] = map[string]interface{}{
		"actionType": "DNS_REQUEST",
		"dnsRequestAction": map[string]interface{}{
			"domain":   g.RandomChoice(c2Domains),
			"protocol": "UDP",
			"blocked":  false,
		},
	}

	fields := g.ApplyOverrides(finding, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_guardduty",
		EventID:    "Backdoor:EC2/C2Activity",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:guardduty",
	}, nil
}
