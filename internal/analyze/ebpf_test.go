package analyze_test

import (
	"strings"
	"testing"

	"github.com/MB3R-Lab/Procrustes/internal/analyze"
	"github.com/MB3R-Lab/Procrustes/internal/model"
	"github.com/MB3R-Lab/Procrustes/internal/scan"
)

func ebpfInput(identity model.Fact) analyze.Input {
	return analyze.Input{
		Goal: model.Goal{
			Contract:  model.Contract{Name: model.GoalContractName, Version: model.GoalContractVersion},
			Scope:     model.Scope{Namespaces: []string{"default"}, Services: []string{"reader"}},
			Operation: model.Operation{ID: "read-items", EntryService: "reader", Method: "GET", Path: "/items", MandatoryTargets: []string{"reader"}},
		},
		Fingerprint:      "sha256:input",
		CollectionSource: "ebpf-obi", SourceDomain: "deployment-a",
		Inventory: scan.Inventory{
			Components: []scan.Component{{
				Namespace: "default", WorkloadKind: "Deployment", WorkloadName: "reader", Container: "reader",
				PodLabels: map[string]string{"app": "reader"}, Source: "manifests/workload.yaml", WorkloadField: ".spec.template",
				Identity:        identity,
				Instrumentation: model.Fact{Status: model.FactAbsent, Message: "No application SDK"},
				Exporter:        model.Fact{Status: model.FactAbsent, Message: "No application exporter"},
				Propagation:     model.Fact{Status: model.FactAbsent, Message: "No application propagation"},
				Replicas:        model.Fact{Status: model.FactConfirmed, Value: "2", Message: "Rendered replicas"},
			}},
			Services:  []scan.KubernetesService{{Namespace: "default", Name: "reader", Selector: map[string]string{"app": "reader"}}},
			Scenarios: []model.Scenario{{Method: "GET", Path: "/items", Source: "scenarios/read.yaml"}},
		},
	}
}

func TestExplicitEBPFSourceDoesNotRequireApplicationSDK(t *testing.T) {
	input := ebpfInput(model.Fact{Status: model.FactAbsent, Message: "No application SDK identity"})
	native := input
	native.CollectionSource, native.SourceDomain = "native", "default"
	nativeReport := analyze.Run(native)
	if nativeReport.GoalStatus != model.CapabilityBlocked {
		t.Fatalf("native SDK checks unexpectedly changed: %+v", nativeReport.GoalStatus)
	}
	report := analyze.Run(input)
	if report.GoalStatus != model.CapabilityPartial || len(report.Blockers) != 0 {
		t.Fatalf("operator-selected OBI was blocked or asserted ready: status=%s blockers=%+v", report.GoalStatus, report.Blockers)
	}
	if nativeReport.Contract.Version != model.ReportContractVersion || nativeReport.CollectionPlan.Contract.Version != model.PlanContractVersion ||
		report.Contract.Version != model.ReportContractVersionEBPF || report.CollectionPlan.Contract.Version != model.PlanContractVersionEBPF {
		t.Fatalf("source-specific contract versions incorrect: native=%s/%s ebpf=%s/%s",
			nativeReport.Contract.Version, nativeReport.CollectionPlan.Contract.Version,
			report.Contract.Version, report.CollectionPlan.Contract.Version)
	}
	if len(report.CollectionPlan.TraceSources) != 1 {
		t.Fatalf("missing explicit OBI handoff: %+v", report.CollectionPlan.TraceSources)
	}
	source := report.CollectionPlan.TraceSources[0]
	if source.System != "obi" || source.BeringInput != "ebpf-obi" || source.Domain != "deployment-a" || source.AdapterRequired {
		t.Fatalf("incorrect Bering handoff: %+v", source)
	}
	if report.Services[0].Instrumentation.Status != model.FactUnknown || report.Services[0].Exporter.Status != model.FactUnknown || report.Services[0].Propagation.Status != model.FactUnknown || report.Services[0].Identity.Status != model.FactUnknown {
		t.Fatalf("unobserved OBI coverage was incorrectly established: %+v", report.Services[0])
	}
	for _, finding := range report.Remediation {
		if strings.Contains(strings.ToLower(finding.Action), "sdk") {
			t.Fatalf("OBI remediation falsely requires an application SDK: %+v", finding)
		}
	}
	if report.Fingerprint == nativeReport.Fingerprint {
		t.Fatal("different collection selections have the same fingerprint")
	}
}

func TestEBPFSourcePreservesIdentityEvidenceAndConflicts(t *testing.T) {
	confirmed := ebpfInput(model.Fact{Status: model.FactConfirmed, Value: "reader", Message: "Unique workload identity"})
	report := analyze.Run(confirmed)
	if report.Services[0].Identity.Status != model.FactConfirmed {
		t.Fatalf("confirmed identity was erased: %+v", report.Services[0].Identity)
	}
	conflicted := ebpfInput(model.Fact{Status: model.FactConflict, Value: "reader,other", Message: "Conflicting identities"})
	report = analyze.Run(conflicted)
	if report.Services[0].Identity.Status != model.FactConflict || report.GoalStatus != model.CapabilityBlocked {
		t.Fatalf("real identity conflict was hidden: status=%s identity=%+v", report.GoalStatus, report.Services[0].Identity)
	}
}

func TestGenericEBPFCollectorHandoffKeepsRuntimeCapabilitiesUnknown(t *testing.T) {
	input := ebpfInput(model.Fact{Status: model.FactAbsent, Message: "No application SDK identity"})
	input.CollectionSource = "ebpf-otlp"
	input.Collector = "collector-a"
	report := analyze.Run(input)
	if report.GoalStatus != model.CapabilityPartial || len(report.Blockers) != 0 {
		t.Fatalf("generic collector was blocked or asserted ready: status=%s blockers=%+v", report.GoalStatus, report.Blockers)
	}
	if report.Contract.Version != model.ReportContractVersionEBPFOTLP || report.CollectionPlan.Contract.Version != model.PlanContractVersionEBPFOTLP {
		t.Fatalf("generic contract versions mismatch: report=%s plan=%s", report.Contract.Version, report.CollectionPlan.Contract.Version)
	}
	if len(report.CollectionPlan.TraceSources) != 1 {
		t.Fatalf("generic handoff missing: %+v", report.CollectionPlan.TraceSources)
	}
	source := report.CollectionPlan.TraceSources[0]
	if source.System != "collector-a" || source.BeringInput != "ebpf-otlp" || source.Domain != "deployment-a" || source.AdapterRequired {
		t.Fatalf("generic Bering handoff mismatch: %+v", source)
	}
	service := report.Services[0]
	if service.Identity.Status != model.FactUnknown || service.Instrumentation.Status != model.FactUnknown || service.Exporter.Status != model.FactUnknown || service.Propagation.Status != model.FactUnknown {
		t.Fatalf("static analysis invented collector runtime coverage: %+v", service)
	}
	joined := strings.ToLower(strings.Join(report.Limitations, " "))
	if !strings.Contains(joined, "kernel compatibility") || !strings.Contains(joined, "protocol support") || !strings.Contains(joined, "runtime evidence") {
		t.Fatalf("collector capability unknowns missing: %+v", report.Limitations)
	}
	other := input
	other.Collector = "collector-b"
	if analyze.Run(other).Fingerprint == report.Fingerprint {
		t.Fatal("different declared collectors have the same fingerprint")
	}
}

func TestCollectionSelectionValidation(t *testing.T) {
	for _, item := range []struct{ source, domain string }{{"native", "default"}, {"ebpf-obi", "deployment-a"}, {"ebpf-obi", ""}} {
		if err := analyze.ValidateCollection(item.source, item.domain); err != nil {
			t.Fatalf("valid selection rejected: %+v: %v", item, err)
		}
	}
	for _, item := range []struct{ source, domain string }{{"unknown", "default"}, {"native", "deployment-a"}, {"ebpf-obi", "bad domain"}} {
		if err := analyze.ValidateCollection(item.source, item.domain); err == nil {
			t.Fatalf("invalid selection accepted: %+v", item)
		}
	}
	for _, item := range []struct{ source, collector, domain string }{
		{"ebpf-otlp", "collector-a", "deployment-a"}, {"ebpf-otlp", "COLLECTOR.A", ""},
	} {
		if err := analyze.ValidateCollectionProfile(item.source, item.collector, item.domain); err != nil {
			t.Fatalf("valid generic selection rejected: %+v: %v", item, err)
		}
	}
	for _, item := range []struct{ source, collector, domain string }{
		{"ebpf-otlp", "", "default"}, {"ebpf-otlp", "bad collector", "default"},
		{"native", "collector-a", "default"}, {"ebpf-obi", "collector-a", "default"},
	} {
		if err := analyze.ValidateCollectionProfile(item.source, item.collector, item.domain); err == nil {
			t.Fatalf("invalid generic selection accepted: %+v", item)
		}
	}
}
