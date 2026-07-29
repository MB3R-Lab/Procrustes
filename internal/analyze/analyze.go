package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MB3R-Lab/Procrustes/internal/model"
	"github.com/MB3R-Lab/Procrustes/internal/scan"
)

type Input struct {
	Goal        model.Goal
	Sources     []model.Source
	Fingerprint string
	Inventory   scan.Inventory
}

func Run(input Input) model.Report {
	services := assessServices(input.Goal, input.Inventory)
	operationFacts, matchedScenarios := assessOperation(input.Goal, services, input.Inventory)
	capabilities := assessCapabilities(services, operationFacts)
	blockers, remediation := findings(services, operationFacts)
	limitations := []string{
		"Procrustes evaluates static eligibility only; Bering must validate runtime evidence, coverage, and signal quality.",
		"DECLARED instrumentation and propagation remain runtime assumptions until matching traces are observed.",
	}
	if usesBackendSpecificTracing(services) {
		limitations = append(limitations,
			"Backend-specific tracing may require a source adapter before Bering ingestion; EXPECTED means that the static collection path is complete, not that runtime trace quality is proven.",
		)
	}
	for _, diagnostic := range input.Inventory.Diagnostics {
		limitations = append(limitations, diagnostic)
	}
	limitations = uniqueSorted(limitations)
	plan := model.CollectionPlan{
		Contract:                   model.Contract{Name: model.PlanContractName, Version: model.PlanContractVersion},
		Operation:                  input.Goal.Operation,
		ExpectedServices:           append([]string(nil), input.Goal.Scope.Services...),
		Scenarios:                  matchedScenarios,
		TraceSources:               traceCollectionPlan(services, input.Inventory.TraceSystems),
		RequiredResourceAttributes: []string{"service.name"},
		RecommendedAttributes:      []string{"deployment.environment.name", "service.namespace", "service.version"},
		KnownLimitations:           limitations,
		BeringOverlay:              "bering.overlay.yaml",
	}
	sourceNames := make([]string, 0, len(input.Sources))
	for _, item := range input.Sources {
		sourceNames = append(sourceNames, item.Alias)
	}
	goalStatus := model.CapabilityNotAssessed
	for _, capability := range capabilities {
		if capability.ID == model.CapabilityReplicaAware {
			goalStatus = capability.Status
			break
		}
	}
	return model.Report{
		Contract:       model.Contract{Name: model.ReportContractName, Version: model.ReportContractVersion},
		ToolVersion:    model.ToolVersion,
		Fingerprint:    input.Fingerprint,
		Goal:           input.Goal,
		Sources:        sourceNames,
		GoalStatus:     goalStatus,
		Services:       services,
		TraceSystems:   append([]model.TraceSystem(nil), input.Inventory.TraceSystems...),
		OperationFacts: operationFacts,
		Capabilities:   capabilities,
		Blockers:       blockers,
		Remediation:    remediation,
		CollectionPlan: plan,
		Limitations:    limitations,
	}
}

func traceCollectionPlan(services []model.ServiceAssessment, systems []model.TraceSystem) []model.TraceCollection {
	used := map[string]struct{}{}
	for _, service := range services {
		if !strings.Contains(service.Exporter.Message, "backend-specific source adapter") {
			continue
		}
		for _, name := range strings.Split(service.Exporter.Value, ",") {
			used[strings.TrimSpace(name)] = struct{}{}
		}
	}
	var result []model.TraceCollection
	for _, system := range systems {
		if system.Role != "backend" {
			continue
		}
		if _, exists := used[system.System]; !exists {
			continue
		}
		collection := system.System + " trace query API for the selected scenario and collection window"
		beringInput := "normalized_spans"
		if system.System == "jaeger" {
			collection = "Jaeger /api/traces for the selected services, scenario, and collection window"
		}
		result = append(result, model.TraceCollection{
			System: system.System, Collection: collection, BeringInput: beringInput,
			AdapterRequired: true, Evidence: append([]model.Evidence(nil), system.Evidence...),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].System+"/"+result[i].Evidence[0].Source < result[j].System+"/"+result[j].Evidence[0].Source
	})
	return result
}

func assessServices(goal model.Goal, inventory scan.Inventory) []model.ServiceAssessment {
	namespaceAllowed := func(namespace string) bool {
		for _, wanted := range goal.Scope.Namespaces {
			if wanted == "*" || wanted == namespace {
				return true
			}
		}
		return false
	}
	result := make([]model.ServiceAssessment, 0, len(goal.Scope.Services))
	for _, serviceID := range goal.Scope.Services {
		var candidates []scan.Component
		var conflicting []scan.Component
		for _, component := range inventory.Components {
			if !namespaceAllowed(component.Namespace) {
				continue
			}
			if component.Identity.Status == model.FactConfirmed && component.Identity.Value == serviceID {
				candidates = append(candidates, component)
			}
			if component.Identity.Status == model.FactConflict && containsCSV(component.Identity.Value, serviceID) {
				conflicting = append(conflicting, component)
			}
		}
		if len(candidates) == 0 && len(conflicting) == 0 {
			for _, component := range inventory.Components {
				if !namespaceAllowed(component.Namespace) {
					continue
				}
				if component.WorkloadName == serviceID || componentSelectedByService(component, serviceID, inventory.Services) {
					candidates = append(candidates, component)
				}
			}
		}
		var assessment model.ServiceAssessment
		switch {
		case len(conflicting) > 0:
			component := conflicting[0]
			assessment = fromComponent(serviceID, component, inventory.Services)
			assessment.Identity = cloneFact(component.Identity, "service."+serviceID+".identity")
		case len(candidates) == 0:
			assessment = missingService(serviceID)
		case len(candidates) > 1:
			evidence := []model.Evidence{}
			values := []string{}
			for _, component := range candidates {
				evidence = append(evidence, model.Evidence{Source: component.Source, Field: component.WorkloadField})
				values = append(values, component.Namespace+"/"+component.WorkloadName+"/"+component.Container)
			}
			sort.Strings(values)
			assessment = fromComponent(serviceID, candidates[0], inventory.Services)
			assessment.Identity = model.Fact{
				ID: "service." + serviceID + ".identity", Status: model.FactConflict, Value: strings.Join(values, ","),
				Message: "Multiple workload containers resolve to the same scoped observability identity", Evidence: evidence,
			}
		default:
			assessment = fromComponent(serviceID, candidates[0], inventory.Services)
		}
		assessment = applyAlternativeTracing(assessment, inventory.TraceSystems)
		result = append(result, assessment)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func applyAlternativeTracing(assessment model.ServiceAssessment, systems []model.TraceSystem) model.ServiceAssessment {
	if assessment.WorkloadEvidence.Status != model.FactConfirmed {
		return assessment
	}
	var instrumentation []model.TraceSystem
	var propagation []model.TraceSystem
	var supporting []model.TraceSystem
	for _, system := range systems {
		matchesService := strings.EqualFold(system.Service, assessment.ID)
		switch {
		case matchesService && system.Role == "instrumentation":
			instrumentation = append(instrumentation, system)
		case matchesService && system.Role == "propagation":
			propagation = append(propagation, system)
		case system.Service == "" && (system.Role == "backend" || system.Role == "configuration" || system.Role == "library"):
			supporting = append(supporting, system)
		}
	}
	if len(instrumentation) == 0 {
		return assessment
	}

	instrumentationEvidence := traceEvidence(instrumentation)
	if assessment.Identity.Status == model.FactAbsent {
		identityStatus := model.FactDeclared
		identityMessage := "A service-scoped tracing initialization declares the trace identity; mapping to service.name remains a Bering adapter responsibility"
		for _, item := range instrumentation {
			if item.Status == model.FactConfirmed {
				identityStatus = model.FactConfirmed
				identityMessage = "A literal service identity in tracing initialization matches the scoped deployment service"
				break
			}
		}
		assessment.Identity = model.Fact{
			ID:       assessment.Identity.ID,
			Status:   identityStatus,
			Value:    assessment.ID,
			Message:  identityMessage,
			Evidence: instrumentationEvidence,
		}
	}
	if assessment.Instrumentation.Status == model.FactAbsent {
		assessment.Instrumentation = model.Fact{
			ID:       assessment.Instrumentation.ID,
			Status:   model.FactDeclared,
			Value:    strings.Join(traceSystemNames(instrumentation), ","),
			Message:  "Non-OpenTelemetry tracing instrumentation is initialized for the service",
			Evidence: instrumentationEvidence,
		}
	}
	if len(propagation) > 0 && (assessment.Propagation.Status == model.FactAbsent || assessment.Propagation.Status == model.FactUnknown) {
		assessment.Propagation = model.Fact{
			ID:       assessment.Propagation.ID,
			Status:   model.FactDeclared,
			Value:    strings.Join(traceSystemNames(propagation), ","),
			Message:  "Legacy distributed-tracing propagation hooks are declared; the runtime carrier format must be verified by Bering",
			Evidence: traceEvidence(propagation),
		}
	}
	if assessment.Exporter.Status == model.FactAbsent || assessment.Exporter.Status == model.FactUnknown {
		evidence := append([]model.Evidence{}, instrumentationEvidence...)
		evidence = append(evidence, traceEvidence(supporting)...)
		status := model.FactUnknown
		message := "A tracing library is initialized, but a matching backend collection path is not fully declared"
		if hasCompleteTracePath(instrumentation, supporting) {
			status = model.FactDeclared
			message = "A service-to-tracing-backend collection path is statically declared; Bering can collect it through the backend-specific source adapter"
		}
		assessment.Exporter = model.Fact{
			ID:       assessment.Exporter.ID,
			Status:   status,
			Value:    strings.Join(traceSystemNames(append(append([]model.TraceSystem{}, instrumentation...), supporting...)), ","),
			Message:  message,
			Evidence: uniqueEvidence(evidence),
		}
	}
	return assessment
}

func usesBackendSpecificTracing(services []model.ServiceAssessment) bool {
	for _, service := range services {
		if strings.Contains(service.Exporter.Message, "backend-specific source adapter") {
			return true
		}
	}
	return false
}

func hasCompleteTracePath(instrumentation, supporting []model.TraceSystem) bool {
	for _, instrument := range instrumentation {
		backendSystem := instrument.System
		if backendSystem == "opentracing" {
			backendSystem = ""
		}
		hasBackend := false
		hasConfiguration := false
		for _, support := range supporting {
			compatible := backendSystem == "" || support.System == backendSystem
			if support.Role == "backend" && compatible {
				hasBackend = true
			}
			if support.Role == "configuration" && compatible {
				hasConfiguration = true
			}
		}
		if hasBackend && hasConfiguration {
			return true
		}
	}
	return false
}

func traceSystemNames(systems []model.TraceSystem) []string {
	names := make([]string, 0, len(systems))
	for _, system := range systems {
		names = append(names, system.System)
	}
	return uniqueSorted(names)
}

func traceEvidence(systems []model.TraceSystem) []model.Evidence {
	var evidence []model.Evidence
	for _, system := range systems {
		evidence = append(evidence, system.Evidence...)
	}
	return uniqueEvidence(evidence)
}

func uniqueEvidence(values []model.Evidence) []model.Evidence {
	seen := map[string]struct{}{}
	result := make([]model.Evidence, 0, len(values))
	for _, value := range values {
		key := value.Source + "\x00" + value.Field
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Source+"/"+result[i].Field < result[j].Source+"/"+result[j].Field
	})
	return result
}

func fromComponent(serviceID string, component scan.Component, services []scan.KubernetesService) model.ServiceAssessment {
	entryNames := []string{}
	for _, service := range services {
		if service.Namespace == component.Namespace && scan.MatchesSelector(component.PodLabels, service.Selector) {
			entryNames = append(entryNames, service.Name)
		}
	}
	sort.Strings(entryNames)
	return model.ServiceAssessment{
		ID: serviceID, Namespace: component.Namespace,
		Workload:  component.WorkloadKind + "/" + component.WorkloadName,
		Container: component.Container, Image: component.Image, Version: component.Version,
		DeploymentEntry: strings.Join(entryNames, ","),
		WorkloadEvidence: model.Fact{
			ID: "service." + serviceID + ".workload", Status: model.FactConfirmed,
			Value:   component.Namespace + "/" + component.WorkloadKind + "/" + component.WorkloadName + "/" + component.Container,
			Message: "A deployable workload container is resolved", Evidence: []model.Evidence{{Source: component.Source, Field: component.WorkloadField}},
		},
		Identity:        cloneFact(component.Identity, "service."+serviceID+".identity"),
		Instrumentation: cloneFact(component.Instrumentation, "service."+serviceID+".instrumentation"),
		Exporter:        cloneFact(component.Exporter, "service."+serviceID+".exporter"),
		Propagation:     cloneFact(component.Propagation, "service."+serviceID+".propagation"),
		Replicas:        cloneFact(component.Replicas, "service."+serviceID+".replicas"),
	}
}

func missingService(serviceID string) model.ServiceAssessment {
	evidence := []model.Evidence{{Source: "scope", Field: "scope.services"}}
	missing := func(suffix, message string) model.Fact {
		return model.Fact{ID: "service." + serviceID + "." + suffix, Status: model.FactAbsent, Message: message, Evidence: evidence}
	}
	unknown := func(suffix, message string) model.Fact {
		return model.Fact{ID: "service." + serviceID + "." + suffix, Status: model.FactUnknown, Message: message, Evidence: evidence}
	}
	return model.ServiceAssessment{
		ID:               serviceID,
		WorkloadEvidence: missing("workload", "No deployable Kubernetes workload was found for the scoped service"),
		Identity:         missing("identity", "No workload container resolves to the scoped observability service identity"),
		Instrumentation:  unknown("instrumentation", "Instrumentation cannot be assessed until the workload identity is resolved"),
		Exporter:         unknown("exporter", "Exporter path cannot be assessed until the workload identity is resolved"),
		Propagation:      unknown("propagation", "Propagation cannot be assessed until the workload identity is resolved"),
		Replicas:         unknown("replicas", "Replica count cannot be assessed until the workload identity is resolved"),
	}
}

func assessOperation(goal model.Goal, services []model.ServiceAssessment, inventory scan.Inventory) ([]model.Fact, []model.Scenario) {
	var entry model.ServiceAssessment
	for _, service := range services {
		if service.ID == goal.Operation.EntryService {
			entry = service
			break
		}
	}
	entryFact := model.Fact{ID: "operation.entrypoint"}
	if entry.DeploymentEntry != "" && entry.WorkloadEvidence.Status == model.FactConfirmed {
		entryFact.Status = model.FactConfirmed
		entryFact.Value = entry.DeploymentEntry
		entryFact.Message = "The operation entry service is exposed by a matching deployment service"
		entryFact.Evidence = append([]model.Evidence(nil), entry.WorkloadEvidence.Evidence...)
	} else if entry.WorkloadEvidence.Status == model.FactConflict {
		entryFact.Status = model.FactConflict
		entryFact.Message = "The operation entrypoint is ambiguous because its service identity conflicts"
		entryFact.Evidence = append([]model.Evidence(nil), entry.Identity.Evidence...)
	} else if entry.Identity.Status == model.FactAbsent {
		entryFact.Status = model.FactAbsent
		entryFact.Message = "The operation entry service was not found"
		entryFact.Evidence = append([]model.Evidence(nil), entry.Identity.Evidence...)
	} else {
		entryFact.Status = model.FactAbsent
		entryFact.Message = "No Kubernetes or Docker Compose entry service selects the operation workload"
		entryFact.Evidence = append([]model.Evidence(nil), entry.Identity.Evidence...)
	}

	matched := []model.Scenario{}
	for _, scenario := range inventory.Scenarios {
		if scenario.Method == goal.Operation.Method && scenario.Path == goal.Operation.Path && scan.RefMatches(scenario.Source, goal.Operation.ScenarioRef) {
			matched = append(matched, scenario)
		}
	}
	scenarioFact := model.Fact{ID: "operation.scenario"}
	if len(matched) == 0 {
		scenarioFact.Status = model.FactAbsent
		scenarioFact.Message = "No matching Tracetest HTTP scenario was found"
		scenarioFact.Evidence = []model.Evidence{{Source: "goal", Field: "operation.method/path/scenario_ref"}}
	} else {
		scenarioFact.Status = model.FactConfirmed
		scenarioFact.Message = "At least one reproducible Tracetest HTTP scenario matches the operation"
		refs := make([]string, 0, len(matched))
		for _, scenario := range matched {
			refs = append(refs, scenario.Source)
			scenarioFact.Evidence = append(scenarioFact.Evidence, model.Evidence{Source: scenario.Source, Field: ".spec.trigger.httpRequest"})
		}
		sort.Strings(refs)
		scenarioFact.Value = strings.Join(refs, ",")
	}
	return []model.Fact{entryFact, scenarioFact}, matched
}

func assessCapabilities(services []model.ServiceAssessment, operationFacts []model.Fact) []model.Capability {
	inventoryFacts := []model.Fact{}
	topologyFacts := []model.Fact{}
	replicaFacts := []model.Fact{}
	for _, service := range services {
		inventoryFacts = append(inventoryFacts, service.WorkloadEvidence)
		topologyFacts = append(topologyFacts, service.WorkloadEvidence, service.Identity, service.Instrumentation, service.Exporter, service.Propagation)
		replicaFacts = append(replicaFacts, service.Replicas)
	}
	inventory := capability(model.CapabilityInventory, inventoryFacts)
	topology := capability(model.CapabilityTopology, topologyFacts)
	operationInput := append(append([]model.Fact{}, topologyFacts...), operationFacts...)
	operation := capability(model.CapabilityOperation, operationInput)
	replicaInput := append(append([]model.Fact{}, operationInput...), replicaFacts...)
	replica := capability(model.CapabilityReplicaAware, replicaInput)
	return []model.Capability{inventory, topology, operation, replica}
}

func capability(id string, facts []model.Fact) model.Capability {
	status := model.CapabilityExpected
	basis := make([]string, 0, len(facts))
	blockers := []string{}
	limitations := []string{}
	for _, fact := range facts {
		basis = append(basis, fact.ID)
		switch fact.Status {
		case model.FactAbsent, model.FactConflict:
			status = model.CapabilityBlocked
			blockers = append(blockers, fact.ID)
		case model.FactUnknown:
			if status != model.CapabilityBlocked {
				status = model.CapabilityPartial
			}
			limitations = append(limitations, fact.Message)
		case model.FactDeclared:
			limitations = append(limitations, fact.Message)
		}
	}
	return model.Capability{ID: id, Status: status, Basis: uniqueSorted(basis), Limitations: uniqueSorted(limitations), Blockers: uniqueSorted(blockers)}
}

type rule struct {
	id         string
	capability string
	action     string
	owner      string
	narrow     bool
}

func findings(services []model.ServiceAssessment, operationFacts []model.Fact) ([]model.Finding, []model.Finding) {
	var blockers []model.Finding
	var remediation []model.Finding
	serviceRules := []struct {
		fact func(model.ServiceAssessment) model.Fact
		rule rule
	}{
		{func(s model.ServiceAssessment) model.Fact { return s.WorkloadEvidence }, rule{"inventory.workload", model.CapabilityInventory, "Provide a rendered Deployment or StatefulSet for the scoped service.", "platform", false}},
		{func(s model.ServiceAssessment) model.Fact { return s.Identity }, rule{"identity.unique", model.CapabilityTopology, "Align deployment and tracing identities to one unique service name.", "service/platform", false}},
		{func(s model.ServiceAssessment) model.Fact { return s.Instrumentation }, rule{"instrumentation.basis", model.CapabilityTopology, "Enable a supported tracing SDK, agent, or Operator instrumentation path for the scoped workload.", "service/platform", true}},
		{func(s model.ServiceAssessment) model.Fact { return s.Exporter }, rule{"export.traces_path", model.CapabilityTopology, "Declare a resolvable OTLP trace endpoint and provide the matching Collector traces pipeline.", "platform/SRE", true}},
		{func(s model.ServiceAssessment) model.Fact { return s.Propagation }, rule{"propagation.http", model.CapabilityTopology, "Enable compatible distributed trace-context propagation for HTTP requests.", "service/platform", true}},
		{func(s model.ServiceAssessment) model.Fact { return s.Replicas }, rule{"replicas.resolved", model.CapabilityReplicaAware, "Provide a positive, rendered replica count for the scoped workload.", "platform", true}},
	}
	for _, service := range services {
		for _, item := range serviceRules {
			fact := item.fact(service)
			if fact.Status == model.FactConfirmed || fact.Status == model.FactDeclared {
				continue
			}
			selectedRule := item.rule
			if selectedRule.id == "export.traces_path" && strings.Contains(fact.Message, "tracing library") {
				selectedRule.action = "Provide a matching tracing backend and statically resolvable exporter or agent configuration."
			}
			finding := toFinding(selectedRule, fact, service.ID)
			remediation = append(remediation, finding)
			if fact.Status == model.FactAbsent || fact.Status == model.FactConflict {
				blockers = append(blockers, finding)
			}
		}
	}
	operationRules := map[string]rule{
		"operation.entrypoint": {"operation.entrypoint", model.CapabilityOperation, "Expose the entry workload through a uniquely linked Kubernetes or Docker Compose service.", "platform/service", false},
		"operation.scenario":   {"operation.scenario", model.CapabilityOperation, "Add or reference a Tracetest HTTP scenario with the selected method and path.", "operation owner", false},
	}
	for _, fact := range operationFacts {
		if fact.Status == model.FactConfirmed || fact.Status == model.FactDeclared {
			continue
		}
		finding := toFinding(operationRules[fact.ID], fact, "")
		remediation = append(remediation, finding)
		if fact.Status == model.FactAbsent || fact.Status == model.FactConflict {
			blockers = append(blockers, finding)
		}
	}
	sortFindings(blockers)
	sortFindings(remediation)
	return blockers, remediation
}

func toFinding(rule rule, fact model.Fact, service string) model.Finding {
	return model.Finding{
		RuleID: rule.id, Status: fact.Status, Service: service, Capability: rule.capability,
		Message: fact.Message, Evidence: fact.Evidence, Action: rule.action, Owner: rule.owner, CanNarrow: rule.narrow,
	}
}

func sortFindings(items []model.Finding) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i].Capability + "/" + items[i].RuleID + "/" + items[i].Service
		right := items[j].Capability + "/" + items[j].RuleID + "/" + items[j].Service
		return left < right
	})
}

func cloneFact(fact model.Fact, id string) model.Fact {
	fact.ID = id
	fact.Evidence = append([]model.Evidence(nil), fact.Evidence...)
	return fact
}

func containsCSV(value, wanted string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.TrimSpace(item) == wanted {
			return true
		}
	}
	return false
}

func componentSelectedByService(component scan.Component, serviceID string, services []scan.KubernetesService) bool {
	for _, service := range services {
		if service.Name == serviceID && service.Namespace == component.Namespace && scan.MatchesSelector(component.PodLabels, service.Selector) {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func CapabilityByID(report model.Report, id string) (model.Capability, error) {
	for _, item := range report.Capabilities {
		if item.ID == id {
			return item, nil
		}
	}
	return model.Capability{}, fmt.Errorf("capability %q not found", id)
}
