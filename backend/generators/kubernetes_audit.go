package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// KubernetesAuditGenerator generates Kubernetes audit log events
type KubernetesAuditGenerator struct {
	BaseGenerator
}

func init() {
	Register(&KubernetesAuditGenerator{})
}

// GetEventType returns the event type for Kubernetes Audit Logs
func (g *KubernetesAuditGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "kubernetes_audit",
		Name:        "Kubernetes Audit Logs",
		Category:    "cloud",
		Description: "Kubernetes API server audit logs for container security",
		EventIDs:    []string{"create", "update", "delete", "get", "list", "exec"},
	}
}

// GetTemplates returns available templates for Kubernetes Audit events
func (g *KubernetesAuditGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "pod_create",
			Name:        "Pod Created",
			Category:    "kubernetes_audit",
			EventID:     "create",
			Format:      "json",
			Description: "Pod creation event",
		},
		{
			ID:          "pod_delete",
			Name:        "Pod Deleted",
			Category:    "kubernetes_audit",
			EventID:     "delete",
			Format:      "json",
			Description: "Pod deletion event",
		},
		{
			ID:          "secret_access",
			Name:        "Secret Accessed",
			Category:    "kubernetes_audit",
			EventID:     "get",
			Format:      "json",
			Description: "Secret read access",
		},
		{
			ID:          "exec_container",
			Name:        "Exec into Container",
			Category:    "kubernetes_audit",
			EventID:     "exec",
			Format:      "json",
			Description: "kubectl exec into container",
		},
		{
			ID:          "configmap_update",
			Name:        "ConfigMap Updated",
			Category:    "kubernetes_audit",
			EventID:     "update",
			Format:      "json",
			Description: "ConfigMap modification",
		},
		{
			ID:          "rbac_change",
			Name:        "RBAC Change",
			Category:    "kubernetes_audit",
			EventID:     "create",
			Format:      "json",
			Description: "Role or RoleBinding change",
		},
	}
}

// Generate creates a Kubernetes Audit event
func (g *KubernetesAuditGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "pod_create":
		return g.generatePodCreate(overrides)
	case "pod_delete":
		return g.generatePodDelete(overrides)
	case "secret_access":
		return g.generateSecretAccess(overrides)
	case "exec_container":
		return g.generateExecContainer(overrides)
	case "configmap_update":
		return g.generateConfigMapUpdate(overrides)
	case "rbac_change":
		return g.generateRBACChange(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *KubernetesAuditGenerator) randomNamespace() string {
	namespaces := []string{"default", "kube-system", "production", "staging", "monitoring", "logging", "ingress-nginx"}
	return g.RandomChoice(namespaces)
}

func (g *KubernetesAuditGenerator) randomPodName() string {
	prefixes := []string{"web", "api", "worker", "nginx", "redis", "postgres", "app"}
	return fmt.Sprintf("%s-%s-%s", g.RandomChoice(prefixes), g.RandomString(5), g.RandomString(5))
}

func (g *KubernetesAuditGenerator) randomImage() string {
	images := []string{
		"nginx:1.25", "redis:7", "postgres:15", "python:3.11",
		"node:20-alpine", "golang:1.21", "busybox:latest",
		"custom-app:v1.2.3", "internal-registry.company.com/app:latest",
	}
	return g.RandomChoice(images)
}

func (g *KubernetesAuditGenerator) randomUser() (string, []string) {
	users := []struct {
		name   string
		groups []string
	}{
		{"system:serviceaccount:default:default", []string{"system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"}},
		{"admin@company.com", []string{"system:masters", "system:authenticated"}},
		{"developer@company.com", []string{"developers", "system:authenticated"}},
		{"system:kube-scheduler", []string{"system:authenticated"}},
		{"system:kube-controller-manager", []string{"system:authenticated"}},
	}
	user := users[g.RandomInt(0, len(users)-1)]
	return user.name, user.groups
}

func (g *KubernetesAuditGenerator) buildBaseEvent(verb, resource, apiVersion string) map[string]interface{} {
	timestamp := time.Now().UTC()
	userName, groups := g.randomUser()
	auditID := uuid.New().String()
	namespace := g.randomNamespace()

	return map[string]interface{}{
		"kind":       "Event",
		"apiVersion": "audit.k8s.io/v1",
		"level":      g.RandomChoice([]string{"Metadata", "Request", "RequestResponse"}),
		"auditID":    auditID,
		"stage":      "ResponseComplete",
		"requestURI": fmt.Sprintf("/api/%s/namespaces/%s/%s", apiVersion, namespace, resource),
		"verb":       verb,
		"user": map[string]interface{}{
			"username": userName,
			"groups":   groups,
		},
		"sourceIPs":               []string{g.RandomIPv4Internal()},
		"userAgent":               g.RandomChoice([]string{"kubectl/v1.28.0", "kube-scheduler/v1.28.0", "argocd/v2.8.0", "helm/v3.12.0"}),
		"objectRef": map[string]interface{}{
			"resource":   resource,
			"namespace":  namespace,
			"apiVersion": apiVersion,
		},
		"responseStatus": map[string]interface{}{
			"metadata": map[string]interface{}{},
			"code":     200,
		},
		"requestReceivedTimestamp": timestamp.Format(time.RFC3339Nano),
		"stageTimestamp":           timestamp.Add(time.Duration(g.RandomInt(1, 100)) * time.Millisecond).Format(time.RFC3339Nano),
		"annotations": map[string]interface{}{
			"authorization.k8s.io/decision": "allow",
			"authorization.k8s.io/reason":   "",
		},
	}
}

func (g *KubernetesAuditGenerator) generatePodCreate(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("create", "pods", "v1")

	podName := g.randomPodName()
	namespace := event["objectRef"].(map[string]interface{})["namespace"].(string)

	event["objectRef"].(map[string]interface{})["name"] = podName
	event["requestObject"] = map[string]interface{}{
		"kind":       "Pod",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      podName,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"containers": []map[string]interface{}{
				{
					"name":  "main",
					"image": g.randomImage(),
				},
			},
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "kubernetes_audit",
		EventID:    "create",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "kube:apiserver:audit",
	}, nil
}

func (g *KubernetesAuditGenerator) generatePodDelete(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("delete", "pods", "v1")

	podName := g.randomPodName()
	event["objectRef"].(map[string]interface{})["name"] = podName

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "kubernetes_audit",
		EventID:    "delete",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "kube:apiserver:audit",
	}, nil
}

func (g *KubernetesAuditGenerator) generateSecretAccess(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("get", "secrets", "v1")

	secretNames := []string{"db-credentials", "api-keys", "tls-cert", "oauth-tokens", "ssh-keys"}
	event["objectRef"].(map[string]interface{})["name"] = g.RandomChoice(secretNames)

	// Secrets access might be suspicious
	event["level"] = "RequestResponse"

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "kubernetes_audit",
		EventID:    "get",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "kube:apiserver:audit",
	}, nil
}

func (g *KubernetesAuditGenerator) generateExecContainer(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("create", "pods/exec", "v1")

	podName := g.randomPodName()
	namespace := event["objectRef"].(map[string]interface{})["namespace"].(string)

	event["objectRef"].(map[string]interface{})["name"] = podName
	event["objectRef"].(map[string]interface{})["subresource"] = "exec"
	event["requestURI"] = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec?command=sh&stdin=true&stdout=true&tty=true", namespace, podName)

	// Exec is high-security event
	event["level"] = "RequestResponse"

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "kubernetes_audit",
		EventID:    "exec",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "kube:apiserver:audit",
	}, nil
}

func (g *KubernetesAuditGenerator) generateConfigMapUpdate(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	event := g.buildBaseEvent("update", "configmaps", "v1")

	configMapNames := []string{"app-config", "nginx-config", "feature-flags", "environment-vars"}
	event["objectRef"].(map[string]interface{})["name"] = g.RandomChoice(configMapNames)

	event["requestObject"] = map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name": event["objectRef"].(map[string]interface{})["name"],
		},
		"data": map[string]interface{}{
			"config.yaml": "# Updated configuration",
		},
	}

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "kubernetes_audit",
		EventID:    "update",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "kube:apiserver:audit",
	}, nil
}

func (g *KubernetesAuditGenerator) generateRBACChange(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	resource := g.RandomChoice([]string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"})
	apiVersion := "rbac.authorization.k8s.io/v1"

	event := g.buildBaseEvent("create", resource, apiVersion)

	roleNames := []string{"admin", "developer-role", "readonly", "deploy-bot", "monitoring-role"}
	event["objectRef"].(map[string]interface{})["name"] = g.RandomChoice(roleNames)
	event["objectRef"].(map[string]interface{})["apiGroup"] = "rbac.authorization.k8s.io"

	// RBAC changes are security-critical
	event["level"] = "RequestResponse"

	fields := g.ApplyOverrides(event, overrides)
	rawEvent, _ := json.MarshalIndent(fields, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "kubernetes_audit",
		EventID:    "create",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "kube:apiserver:audit",
	}, nil
}
