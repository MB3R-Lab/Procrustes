package analyze_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MB3R-Lab/Procrustes/internal/analyze"
	"github.com/MB3R-Lab/Procrustes/internal/config"
	"github.com/MB3R-Lab/Procrustes/internal/model"
	"github.com/MB3R-Lab/Procrustes/internal/output"
	"github.com/MB3R-Lab/Procrustes/internal/scan"
	"github.com/MB3R-Lab/Procrustes/internal/source"
)

func TestReadyFixtureProducesExpectedReplicaAwareHandoff(t *testing.T) {
	report := readyReport(t, nil)
	if report.GoalStatus != model.CapabilityExpected {
		t.Fatalf("goal status = %s, want EXPECTED\nblockers=%+v", report.GoalStatus, report.Blockers)
	}
	if len(report.Blockers) != 0 {
		t.Fatalf("unexpected blockers: %+v", report.Blockers)
	}
	overlay := output.BuildOverlay(report)
	if len(overlay.Services) != 2 {
		t.Fatalf("overlay services = %d, want 2", len(overlay.Services))
	}
	if len(overlay.Endpoints) != 1 || overlay.Endpoints[0].ID != "frontend:GET /checkout" {
		t.Fatalf("unexpected endpoint overlay: %+v", overlay.Endpoints)
	}
}

func TestMutationsConservativelyLimitCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(string) string
		wantStatus model.CapabilityStatus
		wantRule   string
	}{
		{
			name:       "missing instrumentation and identity",
			mutate:     func(raw string) string { return strings.ReplaceAll(raw, "OTEL_", "APP_") },
			wantStatus: model.CapabilityBlocked, wantRule: "identity.unique",
		},
		{
			name: "disabled trace exporter",
			mutate: func(raw string) string {
				return strings.ReplaceAll(raw, "- name: OTEL_EXPORTER_OTLP_ENDPOINT\n              value: http://otel-collector:4317", "- name: OTEL_TRACES_EXPORTER\n              value: none")
			},
			wantStatus: model.CapabilityBlocked, wantRule: "export.traces_path",
		},
		{
			name: "identity conflict",
			mutate: func(raw string) string {
				return strings.Replace(raw, "service.name=$(OTEL_SERVICE_NAME),service.version=1.2.3", "service.name=wrong,service.version=1.2.3", 1)
			},
			wantStatus: model.CapabilityBlocked, wantRule: "identity.unique",
		},
		{
			name: "unresolved secret exporter",
			mutate: func(raw string) string {
				return strings.Replace(raw, "value: http://otel-collector:4317", "valueFrom:\n                secretKeyRef:\n                  name: telemetry\n                  key: endpoint", 1)
			},
			wantStatus: model.CapabilityPartial, wantRule: "export.traces_path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := readyReport(t, tt.mutate)
			if report.GoalStatus != tt.wantStatus {
				t.Fatalf("goal status = %s, want %s; blockers=%+v remediation=%+v", report.GoalStatus, tt.wantStatus, report.Blockers, report.Remediation)
			}
			if !hasRule(report.Remediation, tt.wantRule) {
				t.Fatalf("remediation does not contain rule %q: %+v", tt.wantRule, report.Remediation)
			}
		})
	}
}

func TestMissingScenarioBlocksOperation(t *testing.T) {
	report := readyReport(t, func(raw string) string { return raw })
	report = rerunWithoutScenario(t, report.Goal)
	if report.GoalStatus != model.CapabilityBlocked || !hasRule(report.Blockers, "operation.scenario") {
		t.Fatalf("missing scenario was not a blocker: status=%s blockers=%+v", report.GoalStatus, report.Blockers)
	}
}

func TestCompleteJaegerOpenTracingPathIsExpected(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "ready")
	goal, goalRaw, err := config.LoadGoal(filepath.Join(root, "goal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := source.ReadFiles([]model.Source{{Alias: "ready", Path: root}})
	if err != nil {
		t.Fatal(err)
	}
	for index := range files {
		if strings.HasSuffix(files[index].Ref, "manifests.yaml") {
			files[index].Raw = []byte(strings.ReplaceAll(string(files[index].Raw), "OTEL_", "APP_"))
		}
	}
	files = append(files,
		source.File{Ref: "legacy/cmd/frontend/main.go", Raw: []byte(`package main
func main() { tracing.Init("frontend", jaegerAddress) }
`)},
		source.File{Ref: "legacy/cmd/checkout/main.go", Raw: []byte(`package main
func main() { tracing.Init("checkout", jaegerAddress) }
`)},
		source.File{Ref: "legacy/services/frontend/server.go", Raw: []byte(`package frontend
import "github.com/opentracing/opentracing-go"
func handler() { _ = otgrpc.OpenTracingClientInterceptor }
`)},
		source.File{Ref: "legacy/services/checkout/server.go", Raw: []byte(`package checkout
import "github.com/opentracing/opentracing-go"
func handler() { _ = otgrpc.OpenTracingServerInterceptor }
`)},
		source.File{Ref: "legacy/config.json", Raw: []byte(`{"jaegerAddress":"jaeger:6831"}`)},
		source.File{Ref: "legacy/go.mod", Raw: []byte("require github.com/uber/jaeger-client-go v2.30.0\n")},
		source.File{Ref: "legacy/jaeger.yaml", Raw: []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger
spec:
  replicas: 1
  selector:
    matchLabels: {app: jaeger}
  template:
    metadata:
      labels: {app: jaeger}
    spec:
      containers:
        - name: jaeger
          image: jaegertracing/all-in-one:1.57
`)},
	)

	report := analyze.Run(analyze.Input{
		Goal: goal, Sources: []model.Source{{Alias: "legacy", Path: root}},
		Fingerprint: source.Fingerprint(goalRaw, files), Inventory: scan.Files(files),
	})
	if report.GoalStatus != model.CapabilityExpected {
		t.Fatalf("goal status = %s, want EXPECTED; blockers=%+v remediation=%+v", report.GoalStatus, report.Blockers, report.Remediation)
	}
	if len(report.TraceSystems) == 0 {
		t.Fatal("Jaeger/OpenTracing evidence was not inventoried")
	}
	for _, service := range report.Services {
		if service.Exporter.Status != model.FactDeclared {
			t.Fatalf("%s exporter = %s, want DECLARED: %+v", service.ID, service.Exporter.Status, service.Exporter)
		}
	}
	if hasRule(report.Remediation, "export.traces_path") {
		t.Fatalf("complete Jaeger path produced exporter remediation: %+v", report.Remediation)
	}

	withoutBackend := make([]source.File, 0, len(files)-1)
	for _, file := range files {
		if file.Ref != "legacy/jaeger.yaml" {
			withoutBackend = append(withoutBackend, file)
		}
	}
	partial := analyze.Run(analyze.Input{
		Goal: goal, Sources: []model.Source{{Alias: "legacy", Path: root}},
		Fingerprint: source.Fingerprint(goalRaw, withoutBackend), Inventory: scan.Files(withoutBackend),
	})
	if partial.GoalStatus != model.CapabilityPartial || !hasRule(partial.Remediation, "export.traces_path") {
		t.Fatalf("missing Jaeger backend should be PARTIAL with export remediation: status=%s blockers=%+v remediation=%+v", partial.GoalStatus, partial.Blockers, partial.Remediation)
	}
}

func TestDockerComposeJaegerPathIsExpected(t *testing.T) {
	goal := model.Goal{
		Contract: model.Contract{Name: model.GoalContractName, Version: model.GoalContractVersion},
		Scope:    model.Scope{Namespaces: []string{"compose"}, Services: []string{"frontend", "checkout"}},
		Operation: model.Operation{
			ID: "compose-checkout", EntryService: "frontend", Method: "POST", Path: "/checkout",
			MandatoryTargets: []string{"checkout"}, ScenarioRef: "checkout.tracetest.yaml",
		},
	}
	files := []source.File{
		{Ref: "compose/docker-compose.yml", Raw: []byte(`version: "3.9"
services:
  proxy:
    image: example/proxy:1.0
    ports: ["8080:8080"]
    volumes:
      - ./frontend/jaeger-config.json:/etc/jaeger-config.json
  checkout:
    image: example/checkout:2.0
    deploy:
      replicas: 2
  jaeger-agent:
    image: jaegertracing/all-in-one:1.57
`)},
		{Ref: "frontend/jaeger-config.json", Raw: []byte(`{"service_name":"frontend","reporter":{"localAgentHostPort":"jaeger-agent:6831"}}`)},
		{Ref: "frontend/nginx.conf", Raw: []byte("opentracing on; opentracing_load_tracer libjaegertracing_plugin.so;")},
		{Ref: "checkout/CheckoutService.cpp", Raw: []byte(`SetUpTracer("config/jaeger-config.yml", "checkout");`)},
		{Ref: "checkout/CheckoutHandler.h", Raw: []byte(`opentracing::Tracer::Global()->Inject(span->context(), writer);`)},
		{Ref: "config/jaeger-config.yml", Raw: []byte("reporter:\n  localAgentHostPort: jaeger-agent:6831\n")},
		{Ref: "scenario/checkout.tracetest.yaml", Raw: []byte(`type: Test
spec:
  id: compose-checkout
  trigger:
    type: http
    httpRequest:
      method: POST
      url: http://${var:FRONTEND}/checkout
`)},
	}
	report := analyze.Run(analyze.Input{
		Goal: goal, Sources: []model.Source{{Alias: "compose", Path: "fixture"}},
		Fingerprint: source.Fingerprint([]byte("compose-goal"), files), Inventory: scan.Files(files),
	})
	if report.GoalStatus != model.CapabilityExpected {
		t.Fatalf("goal status = %s, want EXPECTED; blockers=%+v remediation=%+v", report.GoalStatus, report.Blockers, report.Remediation)
	}
	if len(report.Blockers) != 0 || len(report.Remediation) != 0 {
		t.Fatalf("unexpected findings: blockers=%+v remediation=%+v", report.Blockers, report.Remediation)
	}
	overlay := output.BuildOverlay(report)
	if len(overlay.Services) != 2 || len(overlay.Endpoints) != 1 {
		t.Fatalf("unexpected Compose overlay: %+v", overlay)
	}
	if overlay.Services[0].ID != "checkout" || overlay.Services[0].Replicas != 2 {
		t.Fatalf("Compose replicas were not preserved: %+v", overlay.Services)
	}
}

func TestOutputsAreByteStable(t *testing.T) {
	report := readyReport(t, nil)
	left, right := t.TempDir(), t.TempDir()
	if err := output.Write(left, report); err != nil {
		t.Fatal(err)
	}
	if err := output.Write(right, report); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "summary.md", "collection-plan.json", "bering.overlay.yaml"} {
		leftRaw, err := os.ReadFile(filepath.Join(left, name))
		if err != nil {
			t.Fatal(err)
		}
		rightRaw, err := os.ReadFile(filepath.Join(right, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(leftRaw) != string(rightRaw) {
			t.Fatalf("%s is not deterministic", name)
		}
	}
}

func readyReport(t *testing.T, mutate func(string) string) model.Report {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "ready")
	goal, goalRaw, err := config.LoadGoal(filepath.Join(root, "goal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := source.ReadFiles([]model.Source{{Alias: "ready", Path: root}})
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		for index := range files {
			if strings.HasSuffix(files[index].Ref, "manifests.yaml") {
				files[index].Raw = []byte(mutate(string(files[index].Raw)))
			}
		}
	}
	return analyze.Run(analyze.Input{
		Goal: goal, Sources: []model.Source{{Alias: "ready", Path: root}},
		Fingerprint: source.Fingerprint(goalRaw, files), Inventory: scan.Files(files),
	})
}

func rerunWithoutScenario(t *testing.T, goal model.Goal) model.Report {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "ready")
	raw, err := os.ReadFile(filepath.Join(root, "manifests.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files := []source.File{{Ref: "ready/manifests.yaml", Raw: raw}}
	return analyze.Run(analyze.Input{
		Goal: goal, Sources: []model.Source{{Alias: "ready", Path: root}},
		Fingerprint: source.Fingerprint([]byte("goal"), files), Inventory: scan.Files(files),
	})
}

func hasRule(items []model.Finding, rule string) bool {
	for _, item := range items {
		if item.RuleID == rule {
			return true
		}
	}
	return false
}
