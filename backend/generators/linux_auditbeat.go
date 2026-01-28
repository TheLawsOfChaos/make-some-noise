package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// LinuxAuditbeatGenerator generates Linux Auditbeat events in ECS format
type LinuxAuditbeatGenerator struct {
	BaseGenerator
}

func init() {
	Register(&LinuxAuditbeatGenerator{})
}

// GetEventType returns the event type for Linux Auditbeat
func (g *LinuxAuditbeatGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "linux_auditbeat",
		Name:        "Linux Auditbeat",
		Category:    "endpoint",
		Description: "Linux Auditbeat events in Elastic Common Schema (ECS) format",
		EventIDs:    []string{"process", "file", "user_login", "socket", "package"},
	}
}

// GetTemplates returns available templates for Linux Auditbeat events
func (g *LinuxAuditbeatGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "process",
			Name:        "Process Event",
			Category:    "linux_auditbeat",
			EventID:     "process",
			Format:      "json",
			Description: "Process execution and fork events",
		},
		{
			ID:          "file",
			Name:        "File Integrity Event",
			Category:    "linux_auditbeat",
			EventID:     "file",
			Format:      "json",
			Description: "File creation, modification, and deletion events",
		},
		{
			ID:          "user_login",
			Name:        "User Login Event",
			Category:    "linux_auditbeat",
			EventID:     "user_login",
			Format:      "json",
			Description: "User authentication and login events",
		},
		{
			ID:          "socket",
			Name:        "Socket Event",
			Category:    "linux_auditbeat",
			EventID:     "socket",
			Format:      "json",
			Description: "Network socket connection events",
		},
		{
			ID:          "package",
			Name:        "Package Event",
			Category:    "linux_auditbeat",
			EventID:     "package",
			Format:      "json",
			Description: "Package installation and removal events",
		},
	}
}

// Generate creates a Linux Auditbeat event
func (g *LinuxAuditbeatGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "process":
		return g.generateProcess(overrides)
	case "file":
		return g.generateFile(overrides)
	case "user_login":
		return g.generateUserLogin(overrides)
	case "socket":
		return g.generateSocket(overrides)
	case "package":
		return g.generatePackage(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

// RandomLinuxUser generates a random Linux username
func (g *LinuxAuditbeatGenerator) RandomLinuxUser() string {
	users := []string{"root", "admin", "ubuntu", "ec2-user", "centos", "deploy", "www-data", "nginx", "apache"}
	return g.RandomChoice(users)
}

// RandomLinuxProcess generates a random Linux process
func (g *LinuxAuditbeatGenerator) RandomLinuxProcess() (string, string) {
	processes := []struct {
		name string
		path string
	}{
		{"bash", "/usr/bin/bash"},
		{"python3", "/usr/bin/python3"},
		{"node", "/usr/bin/node"},
		{"sshd", "/usr/sbin/sshd"},
		{"nginx", "/usr/sbin/nginx"},
		{"systemd", "/usr/lib/systemd/systemd"},
		{"cron", "/usr/sbin/cron"},
		{"curl", "/usr/bin/curl"},
		{"wget", "/usr/bin/wget"},
		{"apt-get", "/usr/bin/apt-get"},
	}
	proc := processes[g.RandomInt(0, len(processes)-1)]
	return proc.name, proc.path
}

// RandomLinuxHostname generates a random Linux hostname
func (g *LinuxAuditbeatGenerator) RandomLinuxHostname() string {
	prefixes := []string{"web", "app", "db", "api", "worker", "monitor"}
	envs := []string{"prod", "staging", "dev"}
	return fmt.Sprintf("%s-%s-%02d", g.RandomChoice(prefixes), g.RandomChoice(envs), g.RandomInt(1, 10))
}

// generateProcess creates a process event
func (g *LinuxAuditbeatGenerator) generateProcess(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	procName, procPath := g.RandomLinuxProcess()
	parentName, parentPath := g.RandomLinuxProcess()
	user := g.RandomLinuxUser()
	hostname := g.RandomLinuxHostname()

	fields := map[string]interface{}{
		"@timestamp": now.Format(time.RFC3339Nano),
		"ecs": map[string]interface{}{
			"version": "8.0.0",
		},
		"event": map[string]interface{}{
			"kind":     "event",
			"category": []string{"process"},
			"type":     []string{g.RandomChoice([]string{"start", "end", "info"})},
			"action":   g.RandomChoice([]string{"executed", "fork", "exec"}),
			"outcome":  g.RandomChoice([]string{"success", "failure"}),
			"module":   "auditd",
			"dataset":  "auditbeat.auditd",
		},
		"host": map[string]interface{}{
			"name":         hostname,
			"hostname":     hostname,
			"id":           g.RandomGUID(),
			"architecture": "x86_64",
			"os": map[string]interface{}{
				"type":     "linux",
				"family":   "debian",
				"name":     "Ubuntu",
				"version":  "22.04",
				"kernel":   "5.15.0-88-generic",
				"platform": "ubuntu",
			},
			"ip": []string{g.RandomIPv4Internal()},
		},
		"process": map[string]interface{}{
			"pid":        g.RandomInt(1000, 65535),
			"ppid":       g.RandomInt(1, 1000),
			"name":       procName,
			"executable": procPath,
			"args":       []string{procPath, "--config", "/etc/config.yaml"},
			"args_count": 3,
			"command_line": fmt.Sprintf("%s --config /etc/config.yaml", procPath),
			"working_directory": "/home/" + user,
			"start":      now.Add(-time.Duration(g.RandomInt(1, 3600)) * time.Second).Format(time.RFC3339Nano),
			"hash": map[string]interface{}{
				"sha256": g.RandomString(64),
			},
			"parent": map[string]interface{}{
				"pid":        g.RandomInt(1, 1000),
				"name":       parentName,
				"executable": parentPath,
			},
		},
		"user": map[string]interface{}{
			"id":    fmt.Sprintf("%d", g.RandomInt(0, 65534)),
			"name":  user,
			"group": map[string]interface{}{
				"id":   fmt.Sprintf("%d", g.RandomInt(0, 65534)),
				"name": user,
			},
			"effective": map[string]interface{}{
				"id":   fmt.Sprintf("%d", g.RandomInt(0, 65534)),
				"name": user,
			},
		},
		"auditd": map[string]interface{}{
			"sequence": g.RandomInt(100000, 9999999),
			"session":  fmt.Sprintf("%d", g.RandomInt(1, 1000)),
			"result":   g.RandomChoice([]string{"success", "fail"}),
		},
		"agent": map[string]interface{}{
			"type":    "auditbeat",
			"version": "8.11.0",
		},
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "linux_auditbeat",
		EventID:    "process",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "auditbeat",
	}, nil
}

// generateFile creates a file integrity event
func (g *LinuxAuditbeatGenerator) generateFile(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomLinuxHostname()
	user := g.RandomLinuxUser()

	paths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/var/log/auth.log",
		"/home/%s/.bashrc",
		"/home/%s/.ssh/authorized_keys",
		"/opt/app/config.yaml",
		"/var/www/html/index.php",
	}

	filePath := g.RandomChoice(paths)
	if filePath == "/home/%s/.bashrc" || filePath == "/home/%s/.ssh/authorized_keys" {
		filePath = fmt.Sprintf(filePath, user)
	}

	actions := []string{"created", "updated", "deleted", "attributes_modified"}

	fields := map[string]interface{}{
		"@timestamp": now.Format(time.RFC3339Nano),
		"ecs": map[string]interface{}{
			"version": "8.0.0",
		},
		"event": map[string]interface{}{
			"kind":     "event",
			"category": []string{"file"},
			"type":     []string{g.RandomChoice([]string{"creation", "change", "deletion"})},
			"action":   g.RandomChoice(actions),
			"outcome":  "success",
			"module":   "file_integrity",
			"dataset":  "auditbeat.file",
		},
		"host": map[string]interface{}{
			"name":     hostname,
			"hostname": hostname,
			"id":       g.RandomGUID(),
			"os": map[string]interface{}{
				"type":     "linux",
				"family":   "debian",
				"name":     "Ubuntu",
				"version":  "22.04",
				"platform": "ubuntu",
			},
		},
		"file": map[string]interface{}{
			"path":      filePath,
			"name":      filePath[len(filePath)-len(filePath)+1:],
			"directory": filePath[:len(filePath)-1],
			"extension": "",
			"type":      "file",
			"size":      g.RandomInt(100, 100000),
			"inode":     fmt.Sprintf("%d", g.RandomInt(100000, 9999999)),
			"uid":       fmt.Sprintf("%d", g.RandomInt(0, 65534)),
			"gid":       fmt.Sprintf("%d", g.RandomInt(0, 65534)),
			"owner":     user,
			"group":     user,
			"mode":      g.RandomChoice([]string{"0644", "0600", "0755", "0400"}),
			"mtime":     now.Format(time.RFC3339Nano),
			"ctime":     now.Format(time.RFC3339Nano),
			"hash": map[string]interface{}{
				"sha256": g.RandomString(64),
				"sha1":   g.RandomString(40),
				"md5":    g.RandomString(32),
			},
		},
		"user": map[string]interface{}{
			"id":   fmt.Sprintf("%d", g.RandomInt(0, 65534)),
			"name": user,
		},
		"agent": map[string]interface{}{
			"type":    "auditbeat",
			"version": "8.11.0",
		},
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "linux_auditbeat",
		EventID:    "file",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "auditbeat",
	}, nil
}

// generateUserLogin creates a user login event
func (g *LinuxAuditbeatGenerator) generateUserLogin(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomLinuxHostname()
	user := g.RandomLinuxUser()
	srcIP := g.RandomIPv4External()

	outcomes := []string{"success", "failure"}
	outcome := g.RandomChoice(outcomes)

	fields := map[string]interface{}{
		"@timestamp": now.Format(time.RFC3339Nano),
		"ecs": map[string]interface{}{
			"version": "8.0.0",
		},
		"event": map[string]interface{}{
			"kind":     "event",
			"category": []string{"authentication"},
			"type":     []string{g.RandomChoice([]string{"start", "end", "info"})},
			"action":   g.RandomChoice([]string{"logged-in", "logged-out", "session-opened", "session-closed"}),
			"outcome":  outcome,
			"module":   "system",
			"dataset":  "auditbeat.login",
		},
		"host": map[string]interface{}{
			"name":     hostname,
			"hostname": hostname,
			"id":       g.RandomGUID(),
			"os": map[string]interface{}{
				"type":     "linux",
				"family":   "debian",
				"name":     "Ubuntu",
				"version":  "22.04",
				"platform": "ubuntu",
			},
		},
		"source": map[string]interface{}{
			"ip":   srcIP,
			"port": g.RandomPort(),
			"geo": map[string]interface{}{
				"country_iso_code": g.RandomChoice([]string{"US", "CN", "RU", "DE", "BR", "IN"}),
				"city_name":        g.RandomChoice([]string{"New York", "Beijing", "Moscow", "Berlin", "Sao Paulo", "Mumbai"}),
			},
		},
		"user": map[string]interface{}{
			"id":   fmt.Sprintf("%d", g.RandomInt(0, 65534)),
			"name": user,
		},
		"process": map[string]interface{}{
			"pid":        g.RandomInt(1000, 65535),
			"name":       "sshd",
			"executable": "/usr/sbin/sshd",
		},
		"system": map[string]interface{}{
			"auth": map[string]interface{}{
				"ssh": map[string]interface{}{
					"method":   g.RandomChoice([]string{"publickey", "password", "keyboard-interactive"}),
					"event":    g.RandomChoice([]string{"Accepted", "Failed", "Invalid"}),
					"geoip":    srcIP,
					"ip":       srcIP,
					"port":     g.RandomPort(),
					"terminal": fmt.Sprintf("pts/%d", g.RandomInt(0, 10)),
				},
			},
		},
		"related": map[string]interface{}{
			"ip":   []string{srcIP},
			"user": []string{user},
		},
		"agent": map[string]interface{}{
			"type":    "auditbeat",
			"version": "8.11.0",
		},
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "linux_auditbeat",
		EventID:    "user_login",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "auditbeat",
	}, nil
}

// generateSocket creates a socket event
func (g *LinuxAuditbeatGenerator) generateSocket(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomLinuxHostname()
	procName, procPath := g.RandomLinuxProcess()
	user := g.RandomLinuxUser()

	fields := map[string]interface{}{
		"@timestamp": now.Format(time.RFC3339Nano),
		"ecs": map[string]interface{}{
			"version": "8.0.0",
		},
		"event": map[string]interface{}{
			"kind":     "event",
			"category": []string{"network"},
			"type":     []string{"connection", g.RandomChoice([]string{"start", "end"})},
			"action":   "socket_opened",
			"outcome":  "success",
			"module":   "auditd",
			"dataset":  "auditbeat.socket",
		},
		"host": map[string]interface{}{
			"name":     hostname,
			"hostname": hostname,
			"id":       g.RandomGUID(),
			"os": map[string]interface{}{
				"type":     "linux",
				"platform": "ubuntu",
			},
		},
		"source": map[string]interface{}{
			"ip":   g.RandomIPv4Internal(),
			"port": g.RandomPort(),
		},
		"destination": map[string]interface{}{
			"ip":   g.RandomIPv4External(),
			"port": g.RandomCommonPort(),
		},
		"network": map[string]interface{}{
			"type":      "ipv4",
			"transport": g.RandomChoice([]string{"tcp", "udp"}),
			"direction": g.RandomChoice([]string{"egress", "ingress"}),
		},
		"process": map[string]interface{}{
			"pid":        g.RandomInt(1000, 65535),
			"name":       procName,
			"executable": procPath,
		},
		"user": map[string]interface{}{
			"id":   fmt.Sprintf("%d", g.RandomInt(0, 65534)),
			"name": user,
		},
		"agent": map[string]interface{}{
			"type":    "auditbeat",
			"version": "8.11.0",
		},
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "linux_auditbeat",
		EventID:    "socket",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "auditbeat",
	}, nil
}

// generatePackage creates a package event
func (g *LinuxAuditbeatGenerator) generatePackage(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	now := time.Now().UTC()
	hostname := g.RandomLinuxHostname()

	packages := []struct {
		name    string
		version string
	}{
		{"nginx", "1.18.0-6ubuntu14"},
		{"openssh-server", "1:8.9p1-3ubuntu0.4"},
		{"python3", "3.10.12-1~22.04.2"},
		{"docker-ce", "5:24.0.7-1~ubuntu.22.04~jammy"},
		{"nodejs", "18.18.0-1nodesource1"},
		{"postgresql-14", "14.10-0ubuntu0.22.04.1"},
		{"redis-server", "6:7.0.15-1~jammy1"},
		{"curl", "7.81.0-1ubuntu1.14"},
	}

	pkg := packages[g.RandomInt(0, len(packages)-1)]
	action := g.RandomChoice([]string{"package-installed", "package-removed", "package-updated"})

	fields := map[string]interface{}{
		"@timestamp": now.Format(time.RFC3339Nano),
		"ecs": map[string]interface{}{
			"version": "8.0.0",
		},
		"event": map[string]interface{}{
			"kind":     "state",
			"category": []string{"package"},
			"type":     []string{g.RandomChoice([]string{"installation", "deletion", "change"})},
			"action":   action,
			"module":   "system",
			"dataset":  "auditbeat.package",
		},
		"host": map[string]interface{}{
			"name":     hostname,
			"hostname": hostname,
			"id":       g.RandomGUID(),
			"os": map[string]interface{}{
				"type":     "linux",
				"family":   "debian",
				"name":     "Ubuntu",
				"version":  "22.04",
				"platform": "ubuntu",
			},
		},
		"package": map[string]interface{}{
			"name":         pkg.name,
			"version":      pkg.version,
			"type":         "deb",
			"architecture": "amd64",
			"installed":    now.Format(time.RFC3339),
			"size":         g.RandomInt(10000, 100000000),
		},
		"agent": map[string]interface{}{
			"type":    "auditbeat",
			"version": "8.11.0",
		},
	}

	fields = g.ApplyOverrides(fields, overrides)

	rawEventBytes, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "linux_auditbeat",
		EventID:    "package",
		Timestamp:  now,
		RawEvent:   string(rawEventBytes),
		Fields:     fields,
		Sourcetype: "auditbeat",
	}, nil
}
