package generators

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// Generator interface for all event generators
type Generator interface {
	GetEventType() models.EventType
	GetTemplates() []models.EventTemplate
	Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error)
}

// Registry holds all registered generators
var Registry = make(map[string]Generator)

// Register adds a generator to the registry
func Register(g Generator) {
	Registry[g.GetEventType().ID] = g
}

// GetGenerator returns a generator by event type ID
func GetGenerator(eventTypeID string) (Generator, bool) {
	g, ok := Registry[eventTypeID]
	return g, ok
}

// GetAllEventTypes returns all registered event types
func GetAllEventTypes() []models.EventType {
	types := make([]models.EventType, 0, len(Registry))
	for _, g := range Registry {
		types = append(types, g.GetEventType())
	}
	return types
}

// BaseGenerator provides common functionality for generators
type BaseGenerator struct{}

// RandomString generates a random string of specified length
func (b *BaseGenerator) RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

// RandomInt generates a random integer between min and max (inclusive)
func (b *BaseGenerator) RandomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

// RandomChoice selects a random item from a slice
func (b *BaseGenerator) RandomChoice(choices []string) string {
	if len(choices) == 0 {
		return ""
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(choices))))
	return choices[n.Int64()]
}

// RandomChoiceInterface selects a random item from a slice of interfaces
func (b *BaseGenerator) RandomChoiceInterface(choices []interface{}) interface{} {
	if len(choices) == 0 {
		return nil
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(choices))))
	return choices[n.Int64()]
}

// RandomIPv4Internal generates a random internal IPv4 address
func (b *BaseGenerator) RandomIPv4Internal() string {
	prefixes := []string{"10.", "192.168.", "172.16."}
	prefix := b.RandomChoice(prefixes)
	switch prefix {
	case "10.":
		return fmt.Sprintf("10.%d.%d.%d", b.RandomInt(0, 255), b.RandomInt(0, 255), b.RandomInt(1, 254))
	case "192.168.":
		return fmt.Sprintf("192.168.%d.%d", b.RandomInt(0, 255), b.RandomInt(1, 254))
	case "172.16.":
		return fmt.Sprintf("172.%d.%d.%d", b.RandomInt(16, 31), b.RandomInt(0, 255), b.RandomInt(1, 254))
	}
	return "10.0.0.1"
}

// RandomIPv4External generates a random external IPv4 address
func (b *BaseGenerator) RandomIPv4External() string {
	for {
		ip := net.IPv4(
			byte(b.RandomInt(1, 223)),
			byte(b.RandomInt(0, 255)),
			byte(b.RandomInt(0, 255)),
			byte(b.RandomInt(1, 254)),
		)
		// Exclude private and reserved ranges
		if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsMulticast() {
			return ip.String()
		}
	}
}

// RandomMAC generates a random MAC address
func (b *BaseGenerator) RandomMAC() string {
	mac := make([]byte, 6)
	rand.Read(mac)
	mac[0] = (mac[0] | 2) & 0xfe // Set locally administered, unicast
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// RandomPort generates a random port number
func (b *BaseGenerator) RandomPort() int {
	return b.RandomInt(1024, 65535)
}

// RandomPrivilegedPort generates a random privileged port
func (b *BaseGenerator) RandomPrivilegedPort() int {
	return b.RandomInt(1, 1023)
}

// RandomUsername generates a random username
func (b *BaseGenerator) RandomUsername() string {
	prefixes := []string{"user", "admin", "svc", "app", "sys"}
	return fmt.Sprintf("%s_%s", b.RandomChoice(prefixes), b.RandomString(4))
}

// RandomHostname generates a random hostname
func (b *BaseGenerator) RandomHostname() string {
	prefixes := []string{"WS", "SRV", "DC", "WEB", "DB", "APP"}
	return fmt.Sprintf("%s-%s", b.RandomChoice(prefixes), strings.ToUpper(b.RandomString(6)))
}

// RandomDomain generates a random domain name
func (b *BaseGenerator) RandomDomain() string {
	domains := []string{"CORP", "CONTOSO", "ACME", "FABRIKAM", "NORTHWIND"}
	return b.RandomChoice(domains)
}

// RandomFQDN generates a random fully qualified domain name
func (b *BaseGenerator) RandomFQDN() string {
	return fmt.Sprintf("%s.%s.local", strings.ToLower(b.RandomHostname()), strings.ToLower(b.RandomDomain()))
}

// RandomProcessName generates a random process name
func (b *BaseGenerator) RandomProcessName() string {
	processes := []string{
		"explorer.exe", "chrome.exe", "firefox.exe", "notepad.exe",
		"cmd.exe", "powershell.exe", "svchost.exe", "services.exe",
		"lsass.exe", "winlogon.exe", "csrss.exe", "dwm.exe",
		"taskhostw.exe", "RuntimeBroker.exe", "SearchUI.exe",
	}
	return b.RandomChoice(processes)
}

// RandomPath generates a random Windows path
func (b *BaseGenerator) RandomPath() string {
	bases := []string{
		"C:\\Windows\\System32",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
		"C:\\Users\\%s\\AppData\\Local",
		"C:\\Users\\%s\\Documents",
	}
	base := b.RandomChoice(bases)
	if strings.Contains(base, "%s") {
		base = fmt.Sprintf(base, b.RandomUsername())
	}
	return fmt.Sprintf("%s\\%s", base, b.RandomProcessName())
}

// RandomLinuxPath generates a random Linux path
func (b *BaseGenerator) RandomLinuxPath() string {
	paths := []string{
		"/usr/bin/%s",
		"/usr/local/bin/%s",
		"/opt/%s/bin/%s",
		"/home/%s/.local/bin/%s",
		"/var/log/%s",
	}
	path := b.RandomChoice(paths)
	binaries := []string{"bash", "python3", "node", "java", "nginx", "apache2"}
	return fmt.Sprintf(path, b.RandomChoice(binaries))
}

// RandomGUID generates a random GUID
func (b *BaseGenerator) RandomGUID() string {
	return uuid.New().String()
}

// RandomTimestamp generates a random timestamp within the last hour
func (b *BaseGenerator) RandomTimestamp() time.Time {
	seconds := b.RandomInt(0, 3600)
	return time.Now().Add(-time.Duration(seconds) * time.Second)
}

// RandomSID generates a random Windows SID
func (b *BaseGenerator) RandomSID() string {
	return fmt.Sprintf("S-1-5-21-%d-%d-%d-%d",
		b.RandomInt(100000000, 999999999),
		b.RandomInt(100000000, 999999999),
		b.RandomInt(100000000, 999999999),
		b.RandomInt(1000, 9999))
}

// CommonPorts returns commonly used ports for various services
func (b *BaseGenerator) CommonPorts() map[string]int {
	return map[string]int{
		"http":   80,
		"https":  443,
		"ssh":    22,
		"rdp":    3389,
		"dns":    53,
		"smtp":   25,
		"smtps":  465,
		"ftp":    21,
		"mysql":  3306,
		"mssql":  1433,
		"ldap":   389,
		"ldaps":  636,
		"smb":    445,
		"kerberos": 88,
	}
}

// RandomCommonPort returns a random commonly used port
func (b *BaseGenerator) RandomCommonPort() int {
	ports := b.CommonPorts()
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	return ports[b.RandomChoice(keys)]
}

// ApplyOverrides applies override values to generated fields
func (b *BaseGenerator) ApplyOverrides(fields map[string]interface{}, overrides map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range fields {
		result[k] = v
	}
	for k, v := range overrides {
		result[k] = v
	}
	return result
}
