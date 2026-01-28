package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// AzureActivityGenerator generates Azure Activity Log events
type AzureActivityGenerator struct {
	BaseGenerator
}

func init() {
	Register(&AzureActivityGenerator{})
}

// GetEventType returns the event type for Azure Activity Logs
func (g *AzureActivityGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "azure_activity",
		Name:        "Azure Activity Logs",
		Category:    "cloud",
		Description: "Azure control plane operations - resource management, role assignments, policy changes",
		EventIDs:    []string{"Write", "Delete", "Action"},
	}
}

// GetTemplates returns available templates for Azure Activity Logs
func (g *AzureActivityGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "vm_create",
			Name:        "Create Virtual Machine",
			Category:    "azure_activity",
			EventID:     "Write",
			Format:      "json",
			Description: "Virtual machine creation",
		},
		{
			ID:          "vm_delete",
			Name:        "Delete Virtual Machine",
			Category:    "azure_activity",
			EventID:     "Delete",
			Format:      "json",
			Description: "Virtual machine deletion",
		},
		{
			ID:          "role_assignment",
			Name:        "Role Assignment",
			Category:    "azure_activity",
			EventID:     "Write",
			Format:      "json",
			Description: "RBAC role assignment",
		},
		{
			ID:          "nsg_rule_create",
			Name:        "Create NSG Rule",
			Category:    "azure_activity",
			EventID:     "Write",
			Format:      "json",
			Description: "Network security group rule creation",
		},
		{
			ID:          "storage_key_regen",
			Name:        "Regenerate Storage Key",
			Category:    "azure_activity",
			EventID:     "Action",
			Format:      "json",
			Description: "Storage account key regeneration",
		},
		{
			ID:          "keyvault_secret_get",
			Name:        "Get Key Vault Secret",
			Category:    "azure_activity",
			EventID:     "Action",
			Format:      "json",
			Description: "Key Vault secret retrieval",
		},
	}
}

// Generate creates an Azure Activity Log event
func (g *AzureActivityGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "vm_create":
		return g.generateVMCreate(overrides)
	case "vm_delete":
		return g.generateVMDelete(overrides)
	case "role_assignment":
		return g.generateRoleAssignment(overrides)
	case "nsg_rule_create":
		return g.generateNSGRuleCreate(overrides)
	case "storage_key_regen":
		return g.generateStorageKeyRegen(overrides)
	case "keyvault_secret_get":
		return g.generateKeyVaultSecretGet(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *AzureActivityGenerator) randomSubscriptionID() string {
	return uuid.New().String()
}

func (g *AzureActivityGenerator) randomResourceGroup() string {
	names := []string{"rg-prod-eastus", "rg-dev-westus", "rg-staging-central", "rg-network-hub", "rg-security"}
	return g.RandomChoice(names)
}

func (g *AzureActivityGenerator) randomLocation() string {
	locations := []string{"eastus", "westus2", "centralus", "northeurope", "westeurope", "southeastasia"}
	return g.RandomChoice(locations)
}

func (g *AzureActivityGenerator) randomTenantID() string {
	return uuid.New().String()
}

func (g *AzureActivityGenerator) randomPrincipalName() string {
	names := []string{"admin@contoso.com", "devops@contoso.com", "security@contoso.com", "ServicePrincipal-Deploy", "ManagedIdentity-VM"}
	return g.RandomChoice(names)
}

func (g *AzureActivityGenerator) buildBaseEvent(operationName, category, status, subscriptionID, resourceGroup string) map[string]interface{} {
	timestamp := time.Now().UTC()
	return map[string]interface{}{
		"time":            timestamp.Format(time.RFC3339),
		"resourceId":      "",
		"operationName":   operationName,
		"category":        category,
		"resultType":      status,
		"resultSignature": "Succeeded",
		"durationMs":      g.RandomInt(100, 5000),
		"callerIpAddress": g.RandomIPv4External(),
		"correlationId":   uuid.New().String(),
		"identity": map[string]interface{}{
			"authorization": map[string]interface{}{
				"scope":  fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroup),
				"action": operationName,
			},
			"claims": map[string]interface{}{
				"name": g.randomPrincipalName(),
				"oid":  uuid.New().String(),
				"tid":  g.randomTenantID(),
			},
		},
		"level":      "Informational",
		"location":   g.randomLocation(),
		"properties": map[string]interface{}{},
	}
}

func (g *AzureActivityGenerator) generateVMCreate(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	subscriptionID := g.randomSubscriptionID()
	resourceGroup := g.randomResourceGroup()
	vmName := fmt.Sprintf("vm-%s-%s", g.RandomChoice([]string{"web", "app", "db", "worker"}), g.RandomString(4))

	event := g.buildBaseEvent("Microsoft.Compute/virtualMachines/write", "Administrative", "Succeeded", subscriptionID, resourceGroup)
	event["resourceId"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s", subscriptionID, resourceGroup, vmName)

	event["properties"] = map[string]interface{}{
		"statusCode":    "Created",
		"statusMessage": "Resource created successfully",
		"serviceRequestId": uuid.New().String(),
		"entity": map[string]interface{}{
			"vmSize":   g.RandomChoice([]string{"Standard_D2s_v3", "Standard_D4s_v3", "Standard_B2ms"}),
			"location": g.randomLocation(),
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_activity",
		EventID:    "Write",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:activity",
	}, nil
}

func (g *AzureActivityGenerator) generateVMDelete(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	subscriptionID := g.randomSubscriptionID()
	resourceGroup := g.randomResourceGroup()
	vmName := fmt.Sprintf("vm-%s-%s", g.RandomChoice([]string{"web", "app", "db", "worker"}), g.RandomString(4))

	event := g.buildBaseEvent("Microsoft.Compute/virtualMachines/delete", "Administrative", "Succeeded", subscriptionID, resourceGroup)
	event["resourceId"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s", subscriptionID, resourceGroup, vmName)

	event["properties"] = map[string]interface{}{
		"statusCode":    "OK",
		"statusMessage": "Resource deleted successfully",
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_activity",
		EventID:    "Delete",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:activity",
	}, nil
}

func (g *AzureActivityGenerator) generateRoleAssignment(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	subscriptionID := g.randomSubscriptionID()
	resourceGroup := g.randomResourceGroup()

	roles := []string{"Owner", "Contributor", "Reader", "Virtual Machine Contributor", "Storage Blob Data Contributor"}
	event := g.buildBaseEvent("Microsoft.Authorization/roleAssignments/write", "Administrative", "Succeeded", subscriptionID, resourceGroup)
	event["resourceId"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Authorization/roleAssignments/%s", subscriptionID, resourceGroup, uuid.New().String())

	event["properties"] = map[string]interface{}{
		"roleDefinitionId": fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", subscriptionID, uuid.New().String()),
		"principalId":      uuid.New().String(),
		"principalType":    g.RandomChoice([]string{"User", "ServicePrincipal", "Group"}),
		"scope":            fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroup),
		"roleName":         g.RandomChoice(roles),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_activity",
		EventID:    "Write",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:activity",
	}, nil
}

func (g *AzureActivityGenerator) generateNSGRuleCreate(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	subscriptionID := g.randomSubscriptionID()
	resourceGroup := g.randomResourceGroup()
	nsgName := fmt.Sprintf("nsg-%s", g.RandomChoice([]string{"web", "app", "db", "default"}))
	ruleName := fmt.Sprintf("Allow-%s", g.RandomChoice([]string{"SSH", "RDP", "HTTPS", "HTTP", "SQL"}))

	event := g.buildBaseEvent("Microsoft.Network/networkSecurityGroups/securityRules/write", "Administrative", "Succeeded", subscriptionID, resourceGroup)
	event["resourceId"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s/securityRules/%s", subscriptionID, resourceGroup, nsgName, ruleName)

	event["properties"] = map[string]interface{}{
		"statusCode":    "Created",
		"statusMessage": "Security rule created",
		"entity": map[string]interface{}{
			"protocol":                 g.RandomChoice([]string{"TCP", "UDP", "*"}),
			"sourcePortRange":          "*",
			"destinationPortRange":     g.RandomChoice([]string{"22", "3389", "443", "80", "1433"}),
			"sourceAddressPrefix":      g.RandomChoice([]string{"*", "Internet", "10.0.0.0/8"}),
			"destinationAddressPrefix": "*",
			"access":                   "Allow",
			"priority":                 g.RandomInt(100, 4096),
			"direction":                "Inbound",
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_activity",
		EventID:    "Write",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:activity",
	}, nil
}

func (g *AzureActivityGenerator) generateStorageKeyRegen(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	subscriptionID := g.randomSubscriptionID()
	resourceGroup := g.randomResourceGroup()
	storageAccount := fmt.Sprintf("st%s%s", g.RandomChoice([]string{"prod", "dev", "backup"}), g.RandomString(6))

	event := g.buildBaseEvent("Microsoft.Storage/storageAccounts/regenerateKey/action", "Administrative", "Succeeded", subscriptionID, resourceGroup)
	event["resourceId"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", subscriptionID, resourceGroup, storageAccount)

	event["properties"] = map[string]interface{}{
		"statusCode": "OK",
		"entity": map[string]interface{}{
			"keyName": g.RandomChoice([]string{"key1", "key2"}),
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_activity",
		EventID:    "Action",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:activity",
	}, nil
}

func (g *AzureActivityGenerator) generateKeyVaultSecretGet(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	subscriptionID := g.randomSubscriptionID()
	resourceGroup := g.randomResourceGroup()
	vaultName := fmt.Sprintf("kv-%s-%s", g.RandomChoice([]string{"prod", "dev", "shared"}), g.RandomString(4))
	secretName := g.RandomChoice([]string{"DatabasePassword", "ApiKey", "ConnectionString", "EncryptionKey", "CertificateSecret"})

	event := g.buildBaseEvent("Microsoft.KeyVault/vaults/secrets/read", "Administrative", "Succeeded", subscriptionID, resourceGroup)
	event["resourceId"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s/secrets/%s", subscriptionID, resourceGroup, vaultName, secretName)

	event["properties"] = map[string]interface{}{
		"statusCode":      "OK",
		"requestUri":      fmt.Sprintf("https://%s.vault.azure.net/secrets/%s?api-version=7.3", vaultName, secretName),
		"id":              fmt.Sprintf("https://%s.vault.azure.net/secrets/%s/%s", vaultName, secretName, g.RandomString(32)),
		"clientInfo":      "AzureCLI/2.50.0",
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "azure_activity",
		EventID:    "Action",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "azure:activity",
	}, nil
}
