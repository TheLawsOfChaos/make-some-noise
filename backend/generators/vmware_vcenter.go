package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// VMwareVCenterGenerator generates VMware vCenter events
type VMwareVCenterGenerator struct {
	BaseGenerator
}

func init() {
	Register(&VMwareVCenterGenerator{})
}

// GetEventType returns the event type for VMware vCenter
func (g *VMwareVCenterGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "vmware_vcenter",
		Name:        "VMware vCenter",
		Category:    "infrastructure",
		Description: "VMware vCenter VM lifecycle events, alarms, and performance data",
		EventIDs:    []string{"VmCreatedEvent", "VmPoweredOnEvent", "VmPoweredOffEvent", "VmMigratedEvent", "AlarmStatusChangedEvent", "UserLoginSessionEvent"},
	}
}

// GetTemplates returns available templates for VMware vCenter events
func (g *VMwareVCenterGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "vm_created",
			Name:        "VM Created",
			Category:    "vmware_vcenter",
			EventID:     "VmCreatedEvent",
			Format:      "json",
			Description: "Virtual machine created",
		},
		{
			ID:          "vm_powered_on",
			Name:        "VM Powered On",
			Category:    "vmware_vcenter",
			EventID:     "VmPoweredOnEvent",
			Format:      "json",
			Description: "Virtual machine powered on",
		},
		{
			ID:          "vm_powered_off",
			Name:        "VM Powered Off",
			Category:    "vmware_vcenter",
			EventID:     "VmPoweredOffEvent",
			Format:      "json",
			Description: "Virtual machine powered off",
		},
		{
			ID:          "vm_migrated",
			Name:        "VM Migrated (vMotion)",
			Category:    "vmware_vcenter",
			EventID:     "VmMigratedEvent",
			Format:      "json",
			Description: "Virtual machine live migrated",
		},
		{
			ID:          "alarm_triggered",
			Name:        "Alarm Triggered",
			Category:    "vmware_vcenter",
			EventID:     "AlarmStatusChangedEvent",
			Format:      "json",
			Description: "vCenter alarm status changed",
		},
		{
			ID:          "user_login",
			Name:        "User Login",
			Category:    "vmware_vcenter",
			EventID:     "UserLoginSessionEvent",
			Format:      "json",
			Description: "vCenter user login session",
		},
	}
}

// Generate creates a VMware vCenter event
func (g *VMwareVCenterGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "vm_created":
		return g.generateVMCreated(overrides)
	case "vm_powered_on":
		return g.generateVMPoweredOn(overrides)
	case "vm_powered_off":
		return g.generateVMPoweredOff(overrides)
	case "vm_migrated":
		return g.generateVMMigrated(overrides)
	case "alarm_triggered":
		return g.generateAlarmTriggered(overrides)
	case "user_login":
		return g.generateUserLogin(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *VMwareVCenterGenerator) randomVMName() string {
	prefixes := []string{"vm-web", "vm-app", "vm-db", "vm-dev", "vm-prod", "vm-test"}
	return fmt.Sprintf("%s-%03d", g.RandomChoice(prefixes), g.RandomInt(1, 999))
}

func (g *VMwareVCenterGenerator) randomHostName() string {
	return fmt.Sprintf("esxi-%02d.vsphere.local", g.RandomInt(1, 20))
}

func (g *VMwareVCenterGenerator) randomDatacenter() string {
	dcs := []string{"DC-East", "DC-West", "DC-Central", "DC-DR"}
	return g.RandomChoice(dcs)
}

func (g *VMwareVCenterGenerator) randomCluster() string {
	clusters := []string{"Cluster-Prod", "Cluster-Dev", "Cluster-DMZ", "Cluster-Management"}
	return g.RandomChoice(clusters)
}

func (g *VMwareVCenterGenerator) randomDatastore() string {
	datastores := []string{"datastore-ssd-01", "datastore-ssd-02", "datastore-hdd-01", "datastore-nfs-01"}
	return g.RandomChoice(datastores)
}

func (g *VMwareVCenterGenerator) randomMORef(objType string) string {
	prefixes := map[string]string{
		"vm":         "vm",
		"host":       "host",
		"datacenter": "datacenter",
		"cluster":    "domain-c",
		"datastore":  "datastore",
	}
	prefix := prefixes[objType]
	if prefix == "" {
		prefix = "obj"
	}
	return fmt.Sprintf("%s-%d", prefix, g.RandomInt(100, 9999))
}

func (g *VMwareVCenterGenerator) buildBaseEvent(eventType, message string) map[string]interface{} {
	timestamp := time.Now().UTC()
	return map[string]interface{}{
		"key":            g.RandomInt(1000000, 9999999),
		"chainId":        g.RandomInt(1000000, 9999999),
		"createdTime":    timestamp.Format(time.RFC3339),
		"userName":       g.RandomChoice([]string{"administrator@vsphere.local", "admin@corp.local", "svc-backup@corp.local"}),
		"datacenter": map[string]interface{}{
			"name":       g.randomDatacenter(),
			"datacenter": g.randomMORef("datacenter"),
		},
		"computeResource": map[string]interface{}{
			"name":            g.randomCluster(),
			"computeResource": g.randomMORef("cluster"),
		},
		"host": map[string]interface{}{
			"name": g.randomHostName(),
			"host": g.randomMORef("host"),
		},
		"fullFormattedMessage": message,
		"eventType":            eventType,
	}
}

func (g *VMwareVCenterGenerator) generateVMCreated(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	vmName := g.randomVMName()

	event := g.buildBaseEvent("VmCreatedEvent", fmt.Sprintf("Created virtual machine %s on %s", vmName, g.randomHostName()))
	event["vm"] = map[string]interface{}{
		"name": vmName,
		"vm":   g.randomMORef("vm"),
	}
	event["template"] = false

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "vmware_vcenter",
		EventID:    "VmCreatedEvent",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "vmware:vcenter",
	}, nil
}

func (g *VMwareVCenterGenerator) generateVMPoweredOn(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	vmName := g.randomVMName()
	hostName := g.randomHostName()

	event := g.buildBaseEvent("VmPoweredOnEvent", fmt.Sprintf("%s on %s is powered on", vmName, hostName))
	event["vm"] = map[string]interface{}{
		"name": vmName,
		"vm":   g.randomMORef("vm"),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "vmware_vcenter",
		EventID:    "VmPoweredOnEvent",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "vmware:vcenter",
	}, nil
}

func (g *VMwareVCenterGenerator) generateVMPoweredOff(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	vmName := g.randomVMName()
	hostName := g.randomHostName()

	event := g.buildBaseEvent("VmPoweredOffEvent", fmt.Sprintf("%s on %s is powered off", vmName, hostName))
	event["vm"] = map[string]interface{}{
		"name": vmName,
		"vm":   g.randomMORef("vm"),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "vmware_vcenter",
		EventID:    "VmPoweredOffEvent",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "vmware:vcenter",
	}, nil
}

func (g *VMwareVCenterGenerator) generateVMMigrated(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	vmName := g.randomVMName()
	sourceHost := g.randomHostName()
	destHost := g.randomHostName()

	event := g.buildBaseEvent("VmMigratedEvent", fmt.Sprintf("Migration of virtual machine %s from %s to %s completed", vmName, sourceHost, destHost))
	event["vm"] = map[string]interface{}{
		"name": vmName,
		"vm":   g.randomMORef("vm"),
	}
	event["sourceHost"] = map[string]interface{}{
		"name": sourceHost,
		"host": g.randomMORef("host"),
	}
	event["sourceDatastore"] = map[string]interface{}{
		"name":      g.randomDatastore(),
		"datastore": g.randomMORef("datastore"),
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "vmware_vcenter",
		EventID:    "VmMigratedEvent",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "vmware:vcenter",
	}, nil
}

func (g *VMwareVCenterGenerator) generateAlarmTriggered(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()

	alarms := []struct {
		name    string
		message string
	}{
		{"Host CPU usage", "Host CPU usage exceeds 90%"},
		{"Host memory usage", "Host memory usage exceeds 85%"},
		{"Datastore usage on disk", "Datastore disk usage exceeds 80%"},
		{"VM CPU usage", "Virtual machine CPU usage exceeds 95%"},
		{"Host connection state", "Host connection lost"},
		{"Network connectivity", "Network uplink redundancy lost"},
	}
	alarm := alarms[g.RandomInt(0, len(alarms)-1)]

	event := g.buildBaseEvent("AlarmStatusChangedEvent", alarm.message)
	event["alarm"] = map[string]interface{}{
		"name":  alarm.name,
		"alarm": fmt.Sprintf("alarm-%d", g.RandomInt(100, 999)),
	}
	event["entity"] = map[string]interface{}{
		"name":   g.randomHostName(),
		"entity": g.randomMORef("host"),
	}
	event["from"] = "green"
	event["to"] = g.RandomChoice([]string{"yellow", "red"})

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "vmware_vcenter",
		EventID:    "AlarmStatusChangedEvent",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "vmware:vcenter",
	}, nil
}

func (g *VMwareVCenterGenerator) generateUserLogin(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	userName := g.RandomChoice([]string{"administrator@vsphere.local", "admin@corp.local", "operator@corp.local", "readonly@corp.local"})

	event := g.buildBaseEvent("UserLoginSessionEvent", fmt.Sprintf("User %s logged in", userName))
	event["userName"] = userName
	event["ipAddress"] = g.RandomIPv4Internal()
	event["userAgent"] = g.RandomChoice([]string{
		"VMware vSphere Client/7.0.3",
		"VMware-client/6.7.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"PowerCLI/12.7.0",
	})
	event["locale"] = "en_US"
	event["sessionId"] = uuid.New().String()

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "vmware_vcenter",
		EventID:    "UserLoginSessionEvent",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "vmware:vcenter",
	}, nil
}
