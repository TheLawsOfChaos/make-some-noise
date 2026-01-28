package generators

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// CiscoASAGenerator generates Cisco ASA firewall events
type CiscoASAGenerator struct {
	BaseGenerator
}

func init() {
	Register(&CiscoASAGenerator{})
}

// GetEventType returns the event type for Cisco ASA
func (g *CiscoASAGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "cisco_asa",
		Name:        "Cisco ASA",
		Category:    "network",
		Description: "Cisco ASA Firewall events including connections, ACL denies, and VPN sessions",
		EventIDs:    []string{"106001", "106006", "106015", "106023", "302013", "302014", "302015", "302016", "113039", "111008"},
	}
}

// GetTemplates returns available templates for Cisco ASA events
func (g *CiscoASAGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "302013",
			Name:        "Connection Built (Inbound)",
			Category:    "cisco_asa",
			EventID:     "302013",
			Format:      "syslog",
			Description: "Built inbound TCP/UDP connection",
		},
		{
			ID:          "302014",
			Name:        "Connection Teardown",
			Category:    "cisco_asa",
			EventID:     "302014",
			Format:      "syslog",
			Description: "Teardown TCP connection",
		},
		{
			ID:          "302015",
			Name:        "Connection Built (Outbound)",
			Category:    "cisco_asa",
			EventID:     "302015",
			Format:      "syslog",
			Description: "Built outbound UDP connection",
		},
		{
			ID:          "106023",
			Name:        "ACL Deny",
			Category:    "cisco_asa",
			EventID:     "106023",
			Format:      "syslog",
			Description: "Deny by access-list",
		},
		{
			ID:          "113039",
			Name:        "VPN Session Connected",
			Category:    "cisco_asa",
			EventID:     "113039",
			Format:      "syslog",
			Description: "Group user IP VPN session connected",
		},
		{
			ID:          "111008",
			Name:        "User Command",
			Category:    "cisco_asa",
			EventID:     "111008",
			Format:      "syslog",
			Description: "User executed command",
		},
		{
			ID:          "106001",
			Name:        "Inbound Connection Permitted",
			Category:    "cisco_asa",
			EventID:     "106001",
			Format:      "syslog",
			Description: "Inbound TCP connection permitted",
		},
		{
			ID:          "106006",
			Name:        "Connection Denied",
			Category:    "cisco_asa",
			EventID:     "106006",
			Format:      "syslog",
			Description: "Deny inbound connection",
		},
	}
}

// Generate creates a Cisco ASA event
func (g *CiscoASAGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "302013":
		return g.generate302013(overrides)
	case "302014":
		return g.generate302014(overrides)
	case "302015":
		return g.generate302015(overrides)
	case "106023":
		return g.generate106023(overrides)
	case "113039":
		return g.generate113039(overrides)
	case "111008":
		return g.generate111008(overrides)
	case "106001":
		return g.generate106001(overrides)
	case "106006":
		return g.generate106006(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// RandomASAHost generates a random ASA hostname
func (g *CiscoASAGenerator) RandomASAHost() string {
	locations := []string{"dc1", "dc2", "hq", "branch", "dmz", "edge"}
	return fmt.Sprintf("asa-%s-%02d", g.RandomChoice(locations), g.RandomInt(1, 10))
}

// RandomInterface generates a random interface name
func (g *CiscoASAGenerator) RandomInterface() string {
	interfaces := []string{"inside", "outside", "dmz", "management", "vpn", "guest"}
	return g.RandomChoice(interfaces)
}

// RandomACLName generates a random ACL name
func (g *CiscoASAGenerator) RandomACLName() string {
	names := []string{"INSIDE_IN", "OUTSIDE_IN", "DMZ_IN", "GLOBAL_DENY", "VPN_ACCESS", "MGMT_ACCESS"}
	return g.RandomChoice(names)
}

// buildSyslogHeader creates a standard syslog header
func (g *CiscoASAGenerator) buildSyslogHeader(timestamp time.Time, facility, severity int, hostname string) string {
	priority := facility*8 + severity
	return fmt.Sprintf("<%d>%s %s", priority, timestamp.Format("Jan 02 15:04:05"), hostname)
}

// generate302013 creates a built inbound connection event
func (g *CiscoASAGenerator) generate302013(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()
	protocols := []string{"TCP", "UDP"}
	protocol := g.RandomChoice(protocols)

	srcIP := g.RandomIPv4External()
	srcPort := g.RandomPort()
	dstIP := g.RandomIPv4Internal()
	dstPort := g.RandomCommonPort()
	fwdInterface := g.RandomInterface()
	connID := g.RandomInt(100000, 9999999)

	fields := map[string]interface{}{
		"hostname":      hostname,
		"message_id":    "302013",
		"protocol":      protocol,
		"src_interface": "outside",
		"src_ip":        srcIP,
		"src_port":      srcPort,
		"dst_interface": fwdInterface,
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
		"connection_id": connID,
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-6-302013: Built inbound %s connection %d for outside:%s/%d (%s/%d) to %s:%s/%d (%s/%d)",
		g.buildSyslogHeader(now, 20, 6, hostname),
		protocol, connID, srcIP, srcPort, srcIP, srcPort, fwdInterface, dstIP, dstPort, dstIP, dstPort)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "302013",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}

// generate302014 creates a teardown connection event
func (g *CiscoASAGenerator) generate302014(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()

	srcIP := g.RandomIPv4External()
	srcPort := g.RandomPort()
	dstIP := g.RandomIPv4Internal()
	dstPort := g.RandomCommonPort()
	connID := g.RandomInt(100000, 9999999)
	duration := fmt.Sprintf("0:%02d:%02d", g.RandomInt(0, 59), g.RandomInt(0, 59))
	bytes := g.RandomInt(1000, 1000000)
	reasons := []string{"TCP FINs", "TCP Reset-I", "TCP Reset-O", "Idle Timeout", "SYN Timeout"}

	fields := map[string]interface{}{
		"hostname":      hostname,
		"message_id":    "302014",
		"src_interface": "outside",
		"src_ip":        srcIP,
		"src_port":      srcPort,
		"dst_interface": "inside",
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
		"connection_id": connID,
		"duration":      duration,
		"bytes":         bytes,
		"reason":        g.RandomChoice(reasons),
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-6-302014: Teardown TCP connection %d for outside:%s/%d to inside:%s/%d duration %s bytes %d %s",
		g.buildSyslogHeader(now, 20, 6, hostname),
		connID, srcIP, srcPort, dstIP, dstPort, duration, bytes, fields["reason"])

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "302014",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}

// generate302015 creates a built outbound UDP connection event
func (g *CiscoASAGenerator) generate302015(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()

	srcIP := g.RandomIPv4Internal()
	srcPort := g.RandomPort()
	dstIP := g.RandomIPv4External()
	dstPort := g.RandomCommonPort()
	connID := g.RandomInt(100000, 9999999)

	fields := map[string]interface{}{
		"hostname":      hostname,
		"message_id":    "302015",
		"protocol":      "UDP",
		"src_interface": "inside",
		"src_ip":        srcIP,
		"src_port":      srcPort,
		"dst_interface": "outside",
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
		"connection_id": connID,
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-6-302015: Built outbound UDP connection %d for outside:%s/%d (%s/%d) to inside:%s/%d (%s/%d)",
		g.buildSyslogHeader(now, 20, 6, hostname),
		connID, dstIP, dstPort, dstIP, dstPort, srcIP, srcPort, srcIP, srcPort)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "302015",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}

// generate106023 creates an ACL deny event
func (g *CiscoASAGenerator) generate106023(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()
	protocols := []string{"tcp", "udp", "icmp"}
	protocol := g.RandomChoice(protocols)

	srcIP := g.RandomIPv4External()
	srcPort := g.RandomPort()
	dstIP := g.RandomIPv4Internal()
	dstPort := g.RandomCommonPort()
	aclName := g.RandomACLName()
	hitCount := g.RandomInt(1, 100)

	fields := map[string]interface{}{
		"hostname":      hostname,
		"message_id":    "106023",
		"action":        "Deny",
		"protocol":      protocol,
		"src_interface": "outside",
		"src_ip":        srcIP,
		"src_port":      srcPort,
		"dst_interface": "inside",
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
		"acl_name":      aclName,
		"hit_count":     hitCount,
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-4-106023: Deny %s src outside:%s/%d dst inside:%s/%d by access-group \"%s\" [0x0, 0x0]",
		g.buildSyslogHeader(now, 20, 4, hostname),
		protocol, srcIP, srcPort, dstIP, dstPort, aclName)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "106023",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}

// generate113039 creates a VPN session connected event
func (g *CiscoASAGenerator) generate113039(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()
	groups := []string{"VPN-Users", "RemoteAccess", "Contractors", "Admins", "Engineering"}

	username := g.RandomUsername()
	groupName := g.RandomChoice(groups)
	publicIP := g.RandomIPv4External()
	assignedIP := g.RandomIPv4Internal()

	fields := map[string]interface{}{
		"hostname":    hostname,
		"message_id":  "113039",
		"group":       groupName,
		"username":    username,
		"public_ip":   publicIP,
		"assigned_ip": assignedIP,
		"tunnel_type": "SSL",
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-6-113039: Group <%s> User <%s> IP <%s> AnyConnect parent session started.",
		g.buildSyslogHeader(now, 20, 6, hostname),
		groupName, username, publicIP)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "113039",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}

// generate111008 creates a user command event
func (g *CiscoASAGenerator) generate111008(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()
	commands := []string{
		"show running-config",
		"show access-list",
		"show conn",
		"show xlate",
		"show vpn-sessiondb",
		"configure terminal",
		"write memory",
		"reload",
	}

	username := g.RandomUsername()
	command := g.RandomChoice(commands)
	srcIP := g.RandomIPv4Internal()

	fields := map[string]interface{}{
		"hostname":   hostname,
		"message_id": "111008",
		"username":   username,
		"src_ip":     srcIP,
		"command":    command,
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-5-111008: User '%s' executed the '%s' command.",
		g.buildSyslogHeader(now, 20, 5, hostname),
		username, command)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "111008",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}

// generate106001 creates an inbound connection permitted event
func (g *CiscoASAGenerator) generate106001(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()

	srcIP := g.RandomIPv4External()
	dstIP := g.RandomIPv4Internal()
	dstPort := g.RandomCommonPort()

	fields := map[string]interface{}{
		"hostname":      hostname,
		"message_id":    "106001",
		"action":        "Permit",
		"protocol":      "TCP",
		"src_interface": "outside",
		"src_ip":        srcIP,
		"dst_interface": "inside",
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-2-106001: Inbound TCP connection permitted from %s/any to %s/%d flags SYN on interface outside",
		g.buildSyslogHeader(now, 20, 2, hostname),
		srcIP, dstIP, dstPort)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "106001",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}

// generate106006 creates a connection denied event
func (g *CiscoASAGenerator) generate106006(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomASAHost()

	srcIP := g.RandomIPv4External()
	dstIP := g.RandomIPv4Internal()
	dstPort := g.RandomCommonPort()

	fields := map[string]interface{}{
		"hostname":      hostname,
		"message_id":    "106006",
		"action":        "Deny",
		"protocol":      "TCP",
		"src_interface": "outside",
		"src_ip":        srcIP,
		"dst_interface": "inside",
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEvent := fmt.Sprintf("%s %%ASA-2-106006: Deny inbound TCP from %s to %s/%d on interface outside",
		g.buildSyslogHeader(now, 20, 2, hostname),
		srcIP, dstIP, dstPort)

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "cisco_asa",
		EventID:    "106006",
		Timestamp:  now,
		RawEvent:   rawEvent,
		Fields:     fields,
		Sourcetype: "cisco:asa",
	}, nil
}
