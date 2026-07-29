package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MB3R-Lab/Procrustes/internal/model"
	"gopkg.in/yaml.v3"
)

type Overlay struct {
	Name      string            `yaml:"name"`
	Services  []OverlayService  `yaml:"services,omitempty"`
	Endpoints []OverlayEndpoint `yaml:"endpoints,omitempty"`
}

type OverlayService struct {
	ID         string            `yaml:"id"`
	Replicas   int               `yaml:"replicas"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
}

type OverlayEndpoint struct {
	ID           string            `yaml:"id"`
	EntryService string            `yaml:"entry_service"`
	Method       string            `yaml:"method"`
	Path         string            `yaml:"path"`
	Semantics    EndpointSemantics `yaml:"semantics"`
}

type EndpointSemantics struct {
	PredicateMode    string   `yaml:"predicate_mode"`
	MandatoryTargets []string `yaml:"mandatory_targets"`
	DependencyModes  []string `yaml:"dependency_modes"`
	Source           string   `yaml:"source"`
}

func Write(outDir string, report model.Report) error {
	if strings.TrimSpace(outDir) == "" {
		return fmt.Errorf("output directory is required")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	reportRaw, err := marshalJSON(report)
	if err != nil {
		return fmt.Errorf("serialize report: %w", err)
	}
	planRaw, err := marshalJSON(report.CollectionPlan)
	if err != nil {
		return fmt.Errorf("serialize collection plan: %w", err)
	}
	overlayRaw, err := yaml.Marshal(BuildOverlay(report))
	if err != nil {
		return fmt.Errorf("serialize Bering overlay: %w", err)
	}
	files := []struct {
		name string
		raw  []byte
	}{
		{"report.json", reportRaw},
		{"summary.md", []byte(Summary(report))},
		{"collection-plan.json", planRaw},
		{"bering.overlay.yaml", overlayRaw},
	}
	for _, file := range files {
		if err := writeAtomic(filepath.Join(outDir, file.name), file.raw); err != nil {
			return err
		}
	}
	return nil
}

func BuildOverlay(report model.Report) Overlay {
	name := "procrustes-static-context"
	if value := strings.TrimPrefix(report.Fingerprint, "sha256:"); len(value) >= 12 {
		name += "-" + value[:12]
	}
	overlay := Overlay{Name: name}
	for _, service := range report.Services {
		if service.Identity.Status != model.FactConfirmed || service.Replicas.Status != model.FactConfirmed {
			continue
		}
		replicas, err := strconv.Atoi(service.Replicas.Value)
		if err != nil || replicas <= 0 {
			continue
		}
		attributes := map[string]string{
			"procrustes.workload":  service.Namespace + "/" + service.Workload,
			"procrustes.container": service.Container,
		}
		if service.Image != "" {
			attributes["procrustes.image"] = service.Image
		}
		if service.Version != "" {
			attributes["procrustes.service_version"] = service.Version
		}
		overlay.Services = append(overlay.Services, OverlayService{ID: service.ID, Replicas: replicas, Attributes: attributes})
	}
	entryConfirmed, scenarioConfirmed := false, false
	for _, fact := range report.OperationFacts {
		switch fact.ID {
		case "operation.entrypoint":
			entryConfirmed = fact.Status == model.FactConfirmed
		case "operation.scenario":
			scenarioConfirmed = fact.Status == model.FactConfirmed
		}
	}
	if entryConfirmed && scenarioConfirmed {
		endpointID := fmt.Sprintf("%s:%s %s", report.Goal.Operation.EntryService, report.Goal.Operation.Method, report.Goal.Operation.Path)
		overlay.Endpoints = append(overlay.Endpoints, OverlayEndpoint{
			ID: endpointID, EntryService: report.Goal.Operation.EntryService,
			Method: report.Goal.Operation.Method, Path: report.Goal.Operation.Path,
			Semantics: EndpointSemantics{
				PredicateMode: "immediate_response", MandatoryTargets: report.Goal.Operation.MandatoryTargets,
				DependencyModes: []string{"sync"}, Source: "procrustes",
			},
		})
	}
	sort.Slice(overlay.Services, func(i, j int) bool { return overlay.Services[i].ID < overlay.Services[j].ID })
	return overlay
}

func Summary(report model.Report) string {
	var out bytes.Buffer
	fmt.Fprintln(&out, "# Procrustes static fit")
	fmt.Fprintln(&out)
	fmt.Fprintf(&out, "- Goal: `%s %s` on `%s`\n", report.Goal.Operation.Method, report.Goal.Operation.Path, report.Goal.Operation.EntryService)
	fmt.Fprintf(&out, "- Goal status: **%s**\n", report.GoalStatus)
	fmt.Fprintf(&out, "- Fingerprint: `%s`\n", report.Fingerprint)
	fmt.Fprintf(&out, "- Required actions: %d\n", len(report.Remediation))
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "## Capabilities")
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "| Capability | Status |")
	fmt.Fprintln(&out, "|---|---|")
	for _, item := range report.Capabilities {
		fmt.Fprintf(&out, "| `%s` | **%s** |\n", item.ID, item.Status)
	}
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "## Services")
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "| Service | Identity | Instrumentation | Exporter | Propagation | Replicas |")
	fmt.Fprintln(&out, "|---|---|---|---|---|---|")
	for _, item := range report.Services {
		fmt.Fprintf(&out, "| `%s` | %s | %s | %s | %s | %s |\n", item.ID, item.Identity.Status, item.Instrumentation.Status, item.Exporter.Status, item.Propagation.Status, item.Replicas.Status)
	}
	if len(report.TraceSystems) > 0 {
		fmt.Fprintln(&out)
		fmt.Fprintln(&out, "## Detected tracing systems")
		fmt.Fprintln(&out)
		fmt.Fprintln(&out, "| System | Role | Service | Status | Source |")
		fmt.Fprintln(&out, "|---|---|---|---|---|")
		for _, item := range report.TraceSystems {
			service := item.Service
			if service == "" {
				service = "—"
			}
			source := "—"
			if len(item.Evidence) > 0 {
				source = item.Evidence[0].Source
			}
			fmt.Fprintf(&out, "| `%s` | %s | `%s` | %s | `%s` |\n", item.System, item.Role, service, item.Status, source)
		}
	}
	if len(report.Blockers) > 0 {
		fmt.Fprintln(&out)
		fmt.Fprintln(&out, "## Blockers")
		fmt.Fprintln(&out)
		for _, item := range report.Blockers {
			scope := item.Service
			if scope == "" {
				scope = "operation"
			}
			fmt.Fprintf(&out, "- `%s` (%s): %s Action: %s\n", item.RuleID, scope, item.Message, item.Action)
		}
	}
	if len(report.Limitations) > 0 {
		fmt.Fprintln(&out)
		fmt.Fprintln(&out, "## Limitations")
		fmt.Fprintln(&out)
		for _, item := range report.Limitations {
			fmt.Fprintf(&out, "- %s\n", item)
		}
	}
	return out.String()
}

func marshalJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func writeAtomic(path string, raw []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".procrustes-*")
	if err != nil {
		return fmt.Errorf("create temporary output for %s: %w", path, err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary output for %s: %w", path, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary output for %s: %w", path, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		// Windows cannot atomically replace an existing destination. The output
		// directory is explicitly scoped, so replace only this exact file.
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("replace output %s: %w", path, removeErr)
		}
		if retryErr := os.Rename(tempPath, path); retryErr != nil {
			return fmt.Errorf("commit output %s: %w", path, retryErr)
		}
	}
	return nil
}
