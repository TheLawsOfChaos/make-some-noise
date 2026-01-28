package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// AWSCloudTrailGenerator generates AWS CloudTrail events
type AWSCloudTrailGenerator struct {
	BaseGenerator
}

func init() {
	Register(&AWSCloudTrailGenerator{})
}

// GetEventType returns the event type for AWS CloudTrail
func (g *AWSCloudTrailGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "aws_cloudtrail",
		Name:        "AWS CloudTrail",
		Category:    "cloud",
		Description: "AWS CloudTrail API activity logs - who did what, when, and from where",
		EventIDs:    []string{"ConsoleLogin", "AssumeRole", "CreateUser", "DeleteUser", "PutBucketPolicy", "AuthorizeSecurityGroupIngress", "RunInstances", "StopInstances", "CreateAccessKey", "GetSecretValue"},
	}
}

// GetTemplates returns available templates for AWS CloudTrail events
func (g *AWSCloudTrailGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "ConsoleLogin",
			Name:        "Console Login",
			Category:    "aws_cloudtrail",
			EventID:     "ConsoleLogin",
			Format:      "json",
			Description: "AWS Console sign-in event",
		},
		{
			ID:          "AssumeRole",
			Name:        "Assume Role",
			Category:    "aws_cloudtrail",
			EventID:     "AssumeRole",
			Format:      "json",
			Description: "IAM role assumption via STS",
		},
		{
			ID:          "CreateUser",
			Name:        "Create IAM User",
			Category:    "aws_cloudtrail",
			EventID:     "CreateUser",
			Format:      "json",
			Description: "New IAM user creation",
		},
		{
			ID:          "DeleteUser",
			Name:        "Delete IAM User",
			Category:    "aws_cloudtrail",
			EventID:     "DeleteUser",
			Format:      "json",
			Description: "IAM user deletion",
		},
		{
			ID:          "PutBucketPolicy",
			Name:        "Put Bucket Policy",
			Category:    "aws_cloudtrail",
			EventID:     "PutBucketPolicy",
			Format:      "json",
			Description: "S3 bucket policy modification",
		},
		{
			ID:          "AuthorizeSecurityGroupIngress",
			Name:        "Authorize Security Group Ingress",
			Category:    "aws_cloudtrail",
			EventID:     "AuthorizeSecurityGroupIngress",
			Format:      "json",
			Description: "Security group rule addition",
		},
		{
			ID:          "RunInstances",
			Name:        "Run Instances",
			Category:    "aws_cloudtrail",
			EventID:     "RunInstances",
			Format:      "json",
			Description: "EC2 instance launch",
		},
		{
			ID:          "StopInstances",
			Name:        "Stop Instances",
			Category:    "aws_cloudtrail",
			EventID:     "StopInstances",
			Format:      "json",
			Description: "EC2 instance stop",
		},
		{
			ID:          "CreateAccessKey",
			Name:        "Create Access Key",
			Category:    "aws_cloudtrail",
			EventID:     "CreateAccessKey",
			Format:      "json",
			Description: "IAM access key creation",
		},
		{
			ID:          "GetSecretValue",
			Name:        "Get Secret Value",
			Category:    "aws_cloudtrail",
			EventID:     "GetSecretValue",
			Format:      "json",
			Description: "Secrets Manager secret retrieval",
		},
	}
}

// Generate creates an AWS CloudTrail event
func (g *AWSCloudTrailGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "ConsoleLogin":
		return g.generateConsoleLogin(overrides)
	case "AssumeRole":
		return g.generateAssumeRole(overrides)
	case "CreateUser":
		return g.generateCreateUser(overrides)
	case "DeleteUser":
		return g.generateDeleteUser(overrides)
	case "PutBucketPolicy":
		return g.generatePutBucketPolicy(overrides)
	case "AuthorizeSecurityGroupIngress":
		return g.generateAuthorizeSecurityGroupIngress(overrides)
	case "RunInstances":
		return g.generateRunInstances(overrides)
	case "StopInstances":
		return g.generateStopInstances(overrides)
	case "CreateAccessKey":
		return g.generateCreateAccessKey(overrides)
	case "GetSecretValue":
		return g.generateGetSecretValue(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// Helper functions
func (g *AWSCloudTrailGenerator) randomAccountID() string {
	return fmt.Sprintf("%012d", g.RandomInt(100000000000, 999999999999))
}

func (g *AWSCloudTrailGenerator) randomRegion() string {
	regions := []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"}
	return g.RandomChoice(regions)
}

func (g *AWSCloudTrailGenerator) randomARN(accountID, service, resourceType, resourceName string) string {
	return fmt.Sprintf("arn:aws:%s::%s:%s/%s", service, accountID, resourceType, resourceName)
}

func (g *AWSCloudTrailGenerator) randomIAMUser() string {
	users := []string{"admin", "developer", "devops", "security-audit", "backup-service", "deploy-bot", "monitoring"}
	return g.RandomChoice(users) + "-" + g.RandomString(4)
}

func (g *AWSCloudTrailGenerator) randomInstanceType() string {
	types := []string{"t3.micro", "t3.small", "t3.medium", "m5.large", "m5.xlarge", "c5.large", "r5.large"}
	return g.RandomChoice(types)
}

func (g *AWSCloudTrailGenerator) randomUserAgent() string {
	agents := []string{
		"console.amazonaws.com",
		"aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
		"Boto3/1.28.0 Python/3.9.0",
		"aws-sdk-go/1.44.0 (go1.19; linux; amd64)",
		"Terraform/1.5.0",
	}
	return g.RandomChoice(agents)
}

func (g *AWSCloudTrailGenerator) buildBaseEvent(eventName, eventSource, accountID, region string, timestamp time.Time) map[string]interface{} {
	return map[string]interface{}{
		"eventVersion":       "1.08",
		"userIdentity":       map[string]interface{}{},
		"eventTime":          timestamp.UTC().Format(time.RFC3339),
		"eventSource":        eventSource,
		"eventName":          eventName,
		"awsRegion":          region,
		"sourceIPAddress":    g.RandomIPv4External(),
		"userAgent":          g.randomUserAgent(),
		"requestID":          uuid.New().String(),
		"eventID":            uuid.New().String(),
		"readOnly":           false,
		"eventType":          "AwsApiCall",
		"managementEvent":    true,
		"recipientAccountId": accountID,
	}
}

func (g *AWSCloudTrailGenerator) generateConsoleLogin(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	username := g.randomIAMUser()

	success := g.RandomInt(0, 10) > 2 // 80% success rate

	event := g.buildBaseEvent("ConsoleLogin", "signin.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, username),
		"accountId":   accountID,
		"userName":    username,
	}
	event["eventSource"] = "signin.amazonaws.com"
	event["eventName"] = "ConsoleLogin"

	if success {
		event["responseElements"] = map[string]interface{}{
			"ConsoleLogin": "Success",
		}
	} else {
		event["responseElements"] = map[string]interface{}{
			"ConsoleLogin": "Failure",
		}
		event["errorMessage"] = "Failed authentication"
	}

	event["additionalEventData"] = map[string]interface{}{
		"LoginTo":          fmt.Sprintf("https://console.aws.amazon.com/console/home?region=%s", region),
		"MobileVersion":    "No",
		"MFAUsed":          g.RandomChoice([]string{"Yes", "No"}),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "ConsoleLogin",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateAssumeRole(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	roleName := g.RandomChoice([]string{"AdminRole", "DevOpsRole", "ReadOnlyRole", "SecurityAuditRole", "CrossAccountRole"})

	event := g.buildBaseEvent("AssumeRole", "sts.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, g.randomIAMUser()),
		"accountId":   accountID,
	}

	event["requestParameters"] = map[string]interface{}{
		"roleArn":         fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName),
		"roleSessionName": fmt.Sprintf("session-%s", g.RandomString(8)),
		"durationSeconds": g.RandomInt(900, 43200),
	}

	event["responseElements"] = map[string]interface{}{
		"credentials": map[string]interface{}{
			"accessKeyId":  "ASIA" + g.RandomString(16),
			"sessionToken": g.RandomString(256),
			"expiration":   timestamp.Add(time.Hour).UTC().Format(time.RFC3339),
		},
		"assumedRoleUser": map[string]interface{}{
			"assumedRoleId": g.RandomString(21) + ":" + roleName,
			"arn":           fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/session-%s", accountID, roleName, g.RandomString(8)),
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "AssumeRole",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateCreateUser(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	newUser := g.randomIAMUser()

	event := g.buildBaseEvent("CreateUser", "iam.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/admin", accountID),
		"accountId":   accountID,
		"userName":    "admin",
	}

	event["requestParameters"] = map[string]interface{}{
		"userName": newUser,
		"path":     "/",
	}

	event["responseElements"] = map[string]interface{}{
		"user": map[string]interface{}{
			"path":       "/",
			"userName":   newUser,
			"userId":     g.RandomString(21),
			"arn":        fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, newUser),
			"createDate": timestamp.UTC().Format(time.RFC3339),
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "CreateUser",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateDeleteUser(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	deletedUser := g.randomIAMUser()

	event := g.buildBaseEvent("DeleteUser", "iam.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/admin", accountID),
		"accountId":   accountID,
		"userName":    "admin",
	}

	event["requestParameters"] = map[string]interface{}{
		"userName": deletedUser,
	}

	event["responseElements"] = nil

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "DeleteUser",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generatePutBucketPolicy(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	bucketName := fmt.Sprintf("%s-bucket-%s", g.RandomChoice([]string{"data", "logs", "backup", "assets", "config"}), g.RandomString(8))

	event := g.buildBaseEvent("PutBucketPolicy", "s3.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, g.randomIAMUser()),
		"accountId":   accountID,
	}

	event["requestParameters"] = map[string]interface{}{
		"bucketName":   bucketName,
		"bucketPolicy": map[string]interface{}{
			"Version": "2012-10-17",
			"Statement": []map[string]interface{}{
				{
					"Effect":    "Allow",
					"Principal": "*",
					"Action":    "s3:GetObject",
					"Resource":  fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
				},
			},
		},
	}

	event["responseElements"] = nil

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "PutBucketPolicy",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateAuthorizeSecurityGroupIngress(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	sgID := fmt.Sprintf("sg-%s", g.RandomString(17))

	event := g.buildBaseEvent("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, g.randomIAMUser()),
		"accountId":   accountID,
	}

	port := g.RandomChoice([]string{"22", "3389", "443", "80", "3306"})
	event["requestParameters"] = map[string]interface{}{
		"groupId": sgID,
		"ipPermissions": map[string]interface{}{
			"items": []map[string]interface{}{
				{
					"ipProtocol": "tcp",
					"fromPort":   port,
					"toPort":     port,
					"ipRanges": map[string]interface{}{
						"items": []map[string]interface{}{
							{"cidrIp": "0.0.0.0/0"},
						},
					},
				},
			},
		},
	}

	event["responseElements"] = map[string]interface{}{
		"requestId":           uuid.New().String(),
		"_return":             true,
		"securityGroupRuleSet": map[string]interface{}{},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "AuthorizeSecurityGroupIngress",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateRunInstances(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	instanceID := fmt.Sprintf("i-%s", g.RandomString(17))

	event := g.buildBaseEvent("RunInstances", "ec2.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, g.randomIAMUser()),
		"accountId":   accountID,
	}

	event["requestParameters"] = map[string]interface{}{
		"instancesSet": map[string]interface{}{
			"items": []map[string]interface{}{
				{"imageId": fmt.Sprintf("ami-%s", g.RandomString(17))},
			},
		},
		"instanceType": g.randomInstanceType(),
		"minCount":     1,
		"maxCount":     1,
	}

	event["responseElements"] = map[string]interface{}{
		"instancesSet": map[string]interface{}{
			"items": []map[string]interface{}{
				{
					"instanceId":       instanceID,
					"instanceType":     g.randomInstanceType(),
					"instanceState":    map[string]interface{}{"code": 0, "name": "pending"},
					"privateIpAddress": g.RandomIPv4Internal(),
				},
			},
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "RunInstances",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateStopInstances(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	instanceID := fmt.Sprintf("i-%s", g.RandomString(17))

	event := g.buildBaseEvent("StopInstances", "ec2.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, g.randomIAMUser()),
		"accountId":   accountID,
	}

	event["requestParameters"] = map[string]interface{}{
		"instancesSet": map[string]interface{}{
			"items": []map[string]interface{}{
				{"instanceId": instanceID},
			},
		},
		"force": false,
	}

	event["responseElements"] = map[string]interface{}{
		"instancesSet": map[string]interface{}{
			"items": []map[string]interface{}{
				{
					"instanceId":    instanceID,
					"currentState":  map[string]interface{}{"code": 64, "name": "stopping"},
					"previousState": map[string]interface{}{"code": 16, "name": "running"},
				},
			},
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "StopInstances",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateCreateAccessKey(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	targetUser := g.randomIAMUser()

	event := g.buildBaseEvent("CreateAccessKey", "iam.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "IAMUser",
		"principalId": g.RandomString(21),
		"arn":         fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, g.randomIAMUser()),
		"accountId":   accountID,
	}

	event["requestParameters"] = map[string]interface{}{
		"userName": targetUser,
	}

	event["responseElements"] = map[string]interface{}{
		"accessKey": map[string]interface{}{
			"userName":        targetUser,
			"accessKeyId":     "AKIA" + g.RandomString(16),
			"status":          "Active",
			"createDate":      timestamp.UTC().Format(time.RFC3339),
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "CreateAccessKey",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}

func (g *AWSCloudTrailGenerator) generateGetSecretValue(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	accountID := g.randomAccountID()
	region := g.randomRegion()
	secretName := g.RandomChoice([]string{"prod/database/password", "api/keys/external", "config/encryption-key", "service/oauth/client-secret"})

	event := g.buildBaseEvent("GetSecretValue", "secretsmanager.amazonaws.com", accountID, region, timestamp)
	event["userIdentity"] = map[string]interface{}{
		"type":        "AssumedRole",
		"principalId": g.RandomString(21) + ":app-service",
		"arn":         fmt.Sprintf("arn:aws:sts::%s:assumed-role/AppServiceRole/app-service", accountID),
		"accountId":   accountID,
	}

	event["requestParameters"] = map[string]interface{}{
		"secretId":     secretName,
		"versionStage": "AWSCURRENT",
	}

	event["responseElements"] = nil
	event["readOnly"] = true

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "aws_cloudtrail",
		EventID:    "GetSecretValue",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "aws:cloudtrail",
	}, nil
}
