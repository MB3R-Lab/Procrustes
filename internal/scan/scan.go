package scan

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/MB3R-Lab/Procrustes/internal/model"
	"github.com/MB3R-Lab/Procrustes/internal/source"
	"gopkg.in/yaml.v3"
)

type Inventory struct {
	Components   []Component
	Services     []KubernetesService
	Scenarios    []model.Scenario
	TraceSystems []model.TraceSystem
	Diagnostics  []string
}

type Component struct {
	Namespace       string
	WorkloadKind    string
	WorkloadName    string
	Container       string
	Image           string
	Version         string
	PodLabels       map[string]string
	Source          string
	WorkloadField   string
	Identity        model.Fact
	Instrumentation model.Fact
	Exporter        model.Fact
	Propagation     model.Fact
	Replicas        model.Fact
}

type KubernetesService struct {
	Namespace string
	Name      string
	Selector  map[string]string
	Source    string
}

type document struct {
	Value map[string]any
	Ref   string
}

type resolvedValue struct {
	Value string
	Known bool
	Field string
}

var envReferencePattern = regexp.MustCompile(`\$\(([A-Za-z_][A-Za-z0-9_]*)\)`)
var goTracingIdentityPattern = regexp.MustCompile(`(?i)tracing\.init\s*\(\s*["']([^"']+)["']`)
var cppTracingIdentityPattern = regexp.MustCompile(`(?i)setuptracer\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']+)["']`)
var configTracingIdentityPattern = regexp.MustCompile(`(?i)["']service_name["']\s*:\s*["']([^"']+)["']`)
var camelServiceBoundaryPattern = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func Files(files []source.File) Inventory {
	var docs []document
	var diagnostics []string
	traceSystems := collectTraceSystems(files)
	for _, file := range files {
		if !isStructuredFile(file.Ref) {
			continue
		}
		dec := yaml.NewDecoder(bytes.NewReader(file.Raw))
		for index := 1; ; index++ {
			var value map[string]any
			err := dec.Decode(&value)
			if err == io.EOF {
				break
			}
			if err != nil {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: YAML document %d could not be decoded: %v", file.Ref, index, err))
				break
			}
			if len(value) == 0 {
				continue
			}
			docs = append(docs, document{Value: value, Ref: fmt.Sprintf("%s#doc=%d", file.Ref, index)})
		}
	}

	configMaps := collectConfigMaps(docs)
	collectorConfigs := collectCollectorConfigs(configMaps)
	instrumentations := collectInstrumentations(docs)
	services := collectServices(docs)
	composeComponents, composeServices := collectComposeComponents(docs, traceSystems, instrumentations, collectorConfigs)
	services = append(services, composeServices...)
	components := collectComponents(docs, configMaps, instrumentations, services, collectorConfigs)
	components = append(components, composeComponents...)
	scenarios := collectScenarios(docs)
	sort.Slice(components, func(i, j int) bool {
		left := components[i].Namespace + "/" + components[i].WorkloadName + "/" + components[i].Container
		right := components[j].Namespace + "/" + components[j].WorkloadName + "/" + components[j].Container
		return left < right
	})
	sort.Slice(services, func(i, j int) bool {
		return services[i].Namespace+"/"+services[i].Name < services[j].Namespace+"/"+services[j].Name
	})
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].Source < scenarios[j].Source })
	sort.Strings(diagnostics)
	return Inventory{Components: components, Services: services, Scenarios: scenarios, TraceSystems: traceSystems, Diagnostics: diagnostics}
}

type tracePattern struct {
	system string
	terms  []string
}

var tracePatterns = []tracePattern{
	{system: "jaeger", terms: []string{"jaegertracing/", "jaegertracing_plugin", "jaeger-client", "jaeger-config", "jaeger-agent", "jaegeraddress", "jaeger_agent", "jaeger_endpoint"}},
	{system: "opentracing", terms: []string{"opentracing/", "opentracing::", "grpc-opentracing", "otgrpc."}},
	{system: "zipkin", terms: []string{"openzipkin/zipkin", "zipkin-reporter", "zipkin2", "brave-instrumentation", "zipkin_endpoint"}},
	{system: "tempo", terms: []string{"grafana/tempo", "tempo-distributor", "tempo_endpoint"}},
	{system: "skywalking", terms: []string{"apache/skywalking", "skywalking-agent", "sw_agent_"}},
}

func collectTraceSystems(files []source.File) []model.TraceSystem {
	var result []model.TraceSystem
	for _, file := range files {
		lower := strings.ToLower(string(file.Raw))
		ref := filepath.ToSlash(file.Ref)
		lowerRef := strings.ToLower(ref)
		for _, pattern := range tracePatterns {
			if !containsAny(lower, pattern.terms) {
				continue
			}
			service := inferServiceFromRef(ref)
			explicitService := explicitTraceService(lower)
			if explicitService != "" {
				service = explicitService
			}
			role := "configuration"
			status := model.FactDeclared
			message := fmt.Sprintf("%s tracing configuration is present", displayTraceSystem(pattern.system))
			switch {
			case containsBackendImage(lower, pattern.system):
				role = "backend"
				service = ""
				message = fmt.Sprintf("%s backend deployment is present", displayTraceSystem(pattern.system))
			case isDependencyFile(lowerRef):
				role = "library"
				service = ""
				message = fmt.Sprintf("%s tracing library dependency is declared", displayTraceSystem(pattern.system))
			case service != "" && (strings.Contains(lower, "tracing.init(") || strings.Contains(lower, "setuptracer(") || strings.Contains(lower, "newtracer(") || strings.Contains(lower, "initglobaltracer") || strings.Contains(lower, "\"service_name\"") || strings.Contains(lower, "'service_name'")):
				role = "instrumentation"
				message = fmt.Sprintf("%s instrumentation is initialized for the service", displayTraceSystem(pattern.system))
				if explicitService != "" {
					status = model.FactConfirmed
					message = fmt.Sprintf("%s instrumentation declares the service identity as a literal", displayTraceSystem(pattern.system))
				}
			case service != "" && (strings.Contains(lower, "opentracing") || strings.Contains(lower, "otgrpc.") || strings.Contains(lower, "brave")):
				role = "propagation"
				message = fmt.Sprintf("%s propagation hooks are present for the service", displayTraceSystem(pattern.system))
			}
			result = append(result, model.TraceSystem{
				System: pattern.system, Role: role, Service: service, Status: status,
				Message: message, Evidence: []model.Evidence{{Source: file.Ref}},
			})
		}
	}
	result = dedupeTraceSystems(result)
	sort.Slice(result, func(i, j int) bool {
		left := result[i].System + "/" + result[i].Role + "/" + result[i].Service + "/" + result[i].Evidence[0].Source
		right := result[j].System + "/" + result[j].Role + "/" + result[j].Service + "/" + result[j].Evidence[0].Source
		return left < right
	})
	return result
}

func explicitTraceService(value string) string {
	for _, pattern := range []*regexp.Regexp{goTracingIdentityPattern, cppTracingIdentityPattern, configTracingIdentityPattern} {
		match := pattern.FindStringSubmatch(value)
		if len(match) == 2 {
			return strings.TrimSpace(match[1])
		}
	}
	return ""
}

func containsAny(value string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func containsBackendImage(value, system string) bool {
	switch system {
	case "jaeger":
		return strings.Contains(value, "jaegertracing/")
	case "zipkin":
		return strings.Contains(value, "openzipkin/zipkin")
	case "tempo":
		return strings.Contains(value, "grafana/tempo")
	case "skywalking":
		return strings.Contains(value, "apache/skywalking")
	default:
		return false
	}
}

func displayTraceSystem(system string) string {
	switch system {
	case "jaeger":
		return "Jaeger"
	case "opentracing":
		return "OpenTracing"
	case "zipkin":
		return "Zipkin"
	case "tempo":
		return "Grafana Tempo"
	case "skywalking":
		return "Apache SkyWalking"
	default:
		return system
	}
}

func inferServiceFromRef(ref string) string {
	parts := strings.Split(filepath.ToSlash(ref), "/")
	for index := 0; index+1 < len(parts); index++ {
		marker := strings.ToLower(parts[index])
		if marker == "cmd" || marker == "services" || marker == "service" || marker == "src" {
			candidate := strings.TrimSpace(parts[index+1])
			if candidate != "" && candidate != "main.go" {
				return normalizeServiceCandidate(candidate)
			}
		}
	}
	if len(parts) > 1 && serviceAliasAllowed(parts[0]) {
		return normalizeServiceCandidate(parts[0])
	}
	return ""
}

func normalizeServiceCandidate(value string) string {
	value = camelServiceBoundaryPattern.ReplaceAllString(strings.TrimSpace(value), `${1}-${2}`)
	value = strings.NewReplacer("_", "-", " ", "-").Replace(value)
	return strings.ToLower(value)
}

func serviceAliasAllowed(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	reserved := map[string]struct{}{
		"app": {}, "cmd": {}, "compose": {}, "config": {}, "k8s": {}, "legacy": {}, "module": {},
		"preflight": {}, "ready": {}, "scenario": {}, "service": {}, "services": {}, "src": {}, "tests": {},
	}
	_, blocked := reserved[value]
	return !blocked
}

func isDependencyFile(ref string) bool {
	base := strings.ToLower(filepath.Base(strings.Split(ref, "#doc=")[0]))
	return base == "go.mod" || base == "package.json" || base == "pom.xml" || strings.HasPrefix(base, "build.gradle") || base == "requirements.txt"
}

func isStructuredFile(ref string) bool {
	ref = strings.Split(ref, "#doc=")[0]
	switch strings.ToLower(filepath.Ext(ref)) {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

func dedupeTraceSystems(values []model.TraceSystem) []model.TraceSystem {
	seen := map[string]struct{}{}
	result := make([]model.TraceSystem, 0, len(values))
	for _, value := range values {
		key := value.System + "/" + value.Role + "/" + value.Service + "/" + value.Evidence[0].Source
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func collectConfigMaps(docs []document) map[string]map[string]string {
	result := map[string]map[string]string{}
	for _, doc := range docs {
		if stringValue(doc.Value, "kind") != "ConfigMap" {
			continue
		}
		metadata := mapValue(doc.Value, "metadata")
		name := stringValue(metadata, "name")
		if name == "" {
			continue
		}
		namespace := namespaceOf(metadata)
		data := stringMap(mapValue(doc.Value, "data"))
		result[namespace+"/"+name] = data
	}
	return result
}

func collectCollectorConfigs(configMaps map[string]map[string]string) map[string]bool {
	result := map[string]bool{}
	for key, data := range configMaps {
		for _, raw := range data {
			if hasTracePipeline(raw) {
				result[key] = true
				break
			}
		}
	}
	return result
}

func collectInstrumentations(docs []document) map[string]resolvedValue {
	result := map[string]resolvedValue{}
	for _, doc := range docs {
		if stringValue(doc.Value, "kind") != "Instrumentation" {
			continue
		}
		metadata := mapValue(doc.Value, "metadata")
		namespace := namespaceOf(metadata)
		name := stringValue(metadata, "name")
		if name == "" {
			continue
		}
		endpoint := stringValue(mapValue(mapValue(doc.Value, "spec"), "exporter"), "endpoint")
		result[namespace+"/"+name] = resolvedValue{Value: endpoint, Known: endpoint != "", Field: ".spec.exporter.endpoint"}
	}
	return result
}

func collectServices(docs []document) []KubernetesService {
	var result []KubernetesService
	for _, doc := range docs {
		if stringValue(doc.Value, "kind") != "Service" {
			continue
		}
		metadata := mapValue(doc.Value, "metadata")
		name := stringValue(metadata, "name")
		selector := stringMap(mapValue(mapValue(doc.Value, "spec"), "selector"))
		if name == "" || len(selector) == 0 {
			continue
		}
		result = append(result, KubernetesService{Namespace: namespaceOf(metadata), Name: name, Selector: selector, Source: doc.Ref})
	}
	return result
}

func collectComposeComponents(docs []document, traceSystems []model.TraceSystem, instrumentations map[string]resolvedValue, collectorConfigs map[string]bool) ([]Component, []KubernetesService) {
	var components []Component
	var entries []KubernetesService
	for _, doc := range docs {
		if stringValue(doc.Value, "kind") != "" {
			continue
		}
		composeServices := mapValue(doc.Value, "services")
		if len(composeServices) == 0 {
			continue
		}
		names := make([]string, 0, len(composeServices))
		for name := range composeServices {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			service := asMap(composeServices[name])
			if len(service) == 0 {
				continue
			}
			labels := map[string]string{"procrustes.compose.service": name}
			container := name
			if value := stringValue(service, "container_name"); value != "" {
				container = value
			}
			image := stringValue(service, "image")
			env := resolveComposeEnvironment(service)
			identity := identityFact(env, doc.Ref, container)
			if mounted := mountedTraceIdentity(service, traceSystems, doc.Ref, container); mounted.Status != model.FactAbsent {
				identity = mounted
			}
			instrumentation, injectionName := instrumentationFact(env, nil, "compose", instrumentations, doc.Ref, container)
			// Compose destinations are assessed through the generic exporter first;
			// backend-specific tracing is joined later from source/config evidence.
			exporter := exporterFact(env, injectionName, "compose", instrumentations, entries, collectorConfigs, instrumentation, doc.Ref, container)
			propagation := propagationFact(env, instrumentation, doc.Ref, container)
			components = append(components, Component{
				Namespace: "compose", WorkloadKind: "ComposeService", WorkloadName: name, Container: container,
				Image: image, Version: serviceVersion(env, image), PodLabels: labels, Source: doc.Ref, WorkloadField: ".services." + name,
				Identity: identity, Instrumentation: instrumentation, Exporter: exporter,
				Propagation: propagation, Replicas: composeReplicaFact(service, doc.Ref, name),
			})
			if len(sliceValue(service, "ports")) > 0 {
				entries = append(entries, KubernetesService{
					Namespace: "compose", Name: name, Selector: labels, Source: doc.Ref,
				})
			}
		}
	}
	return components, entries
}

func resolveComposeEnvironment(service map[string]any) map[string]resolvedValue {
	result := map[string]resolvedValue{}
	raw, exists := service["environment"]
	if !exists || raw == nil {
		return result
	}
	if values := asMap(raw); len(values) > 0 {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := values[key]
			known := value != nil && !strings.Contains(fmt.Sprint(value), "${")
			result[key] = resolvedValue{Value: fmt.Sprint(value), Known: known, Field: ".services." + key + ".environment." + key}
		}
		return result
	}
	values, ok := raw.([]any)
	if !ok {
		return result
	}
	for _, rawItem := range values {
		item := fmt.Sprint(rawItem)
		parts := strings.SplitN(item, "=", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		value, known := "", false
		if len(parts) == 2 {
			value = parts[1]
			known = !strings.Contains(value, "${")
		}
		result[name] = resolvedValue{Value: value, Known: known, Field: ".services[].environment[" + name + "]"}
	}
	return result
}

func mountedTraceIdentity(service map[string]any, systems []model.TraceSystem, ref, container string) model.Fact {
	volumes := composeVolumeSources(service)
	values := map[string][]model.Evidence{}
	for _, system := range systems {
		if system.Role != "instrumentation" || system.Status != model.FactConfirmed || system.Service == "" {
			continue
		}
		for _, evidence := range system.Evidence {
			if composeVolumeMatches(volumes, evidence.Source) {
				values[system.Service] = append(values[system.Service], evidence)
			}
		}
	}
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	id := "container." + container + ".identity"
	switch len(keys) {
	case 0:
		return model.Fact{ID: id, Status: model.FactAbsent, Message: "No mounted tracing configuration declares the Compose service identity", Evidence: []model.Evidence{{Source: ref, Field: ".services[].volumes"}}}
	case 1:
		return model.Fact{ID: id, Status: model.FactConfirmed, Value: keys[0], Message: "A mounted tracing configuration resolves the Compose service identity", Evidence: uniqueModelEvidence(values[keys[0]])}
	default:
		var evidence []model.Evidence
		for _, key := range keys {
			evidence = append(evidence, values[key]...)
		}
		return model.Fact{ID: id, Status: model.FactConflict, Value: strings.Join(keys, ","), Message: "Mounted tracing configurations declare conflicting Compose service identities", Evidence: uniqueModelEvidence(evidence)}
	}
}

func composeVolumeSources(service map[string]any) []string {
	var result []string
	for _, raw := range sliceValue(service, "volumes") {
		value := strings.TrimSpace(fmt.Sprint(raw))
		if value == "" {
			continue
		}
		source := strings.TrimPrefix(strings.SplitN(value, ":", 2)[0], "./")
		result = append(result, filepath.ToSlash(source))
	}
	return result
}

func composeVolumeMatches(volumes []string, evidenceRef string) bool {
	evidenceRef = filepath.ToSlash(strings.Split(evidenceRef, "#doc=")[0])
	for _, volume := range volumes {
		if evidenceRef == volume || strings.HasSuffix(evidenceRef, "/"+volume) || strings.HasSuffix(volume, "/"+evidenceRef) {
			return true
		}
	}
	return false
}

func composeReplicaFact(service map[string]any, ref, name string) model.Fact {
	id := "workload.replicas"
	value, exists := mapValue(service, "deploy")["replicas"]
	field := ".services." + name + ".deploy.replicas"
	if !exists {
		value, exists = service["scale"]
		field = ".services." + name + ".scale"
	}
	if !exists || value == nil {
		return model.Fact{ID: id, Status: model.FactConfirmed, Value: "1", Message: "Replica count uses the Docker Compose default", Evidence: []model.Evidence{{Source: ref, Field: ".services." + name + ".replicas(default=1)"}}}
	}
	count, ok := intValue(value)
	if !ok {
		return model.Fact{ID: id, Status: model.FactUnknown, Message: "Docker Compose replica count cannot be resolved", Evidence: []model.Evidence{{Source: ref, Field: field}}}
	}
	if count <= 0 {
		return model.Fact{ID: id, Status: model.FactAbsent, Value: strconv.Itoa(count), Message: "Docker Compose replica count must be positive", Evidence: []model.Evidence{{Source: ref, Field: field}}}
	}
	return model.Fact{ID: id, Status: model.FactConfirmed, Value: strconv.Itoa(count), Message: "Docker Compose replica count is resolved", Evidence: []model.Evidence{{Source: ref, Field: field}}}
}

func uniqueModelEvidence(values []model.Evidence) []model.Evidence {
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

func collectComponents(docs []document, configMaps map[string]map[string]string, instrumentations map[string]resolvedValue, services []KubernetesService, collectorConfigs map[string]bool) []Component {
	var result []Component
	for _, doc := range docs {
		kind := stringValue(doc.Value, "kind")
		if kind != "Deployment" && kind != "StatefulSet" && kind != "DaemonSet" {
			continue
		}
		metadata := mapValue(doc.Value, "metadata")
		namespace := namespaceOf(metadata)
		name := stringValue(metadata, "name")
		spec := mapValue(doc.Value, "spec")
		template := mapValue(spec, "template")
		templateMetadata := mapValue(template, "metadata")
		podLabels := stringMap(mapValue(templateMetadata, "labels"))
		annotations := stringMap(mapValue(templateMetadata, "annotations"))
		if len(annotations) == 0 {
			annotations = stringMap(mapValue(metadata, "annotations"))
		}
		replicas := replicaFact(kind, spec, doc.Ref)
		containers := sliceValue(mapValue(template, "spec"), "containers")
		for _, rawContainer := range containers {
			container := asMap(rawContainer)
			containerName := stringValue(container, "name")
			image := stringValue(container, "image")
			env := resolveEnvironment(container, namespace, name, podLabels, annotations, configMaps)
			identity := identityFact(env, doc.Ref, containerName)
			instrumentation, injectionName := instrumentationFact(env, annotations, namespace, instrumentations, doc.Ref, containerName)
			exporter := exporterFact(env, injectionName, namespace, instrumentations, services, collectorConfigs, instrumentation, doc.Ref, containerName)
			propagation := propagationFact(env, instrumentation, doc.Ref, containerName)
			version := serviceVersion(env, image)
			result = append(result, Component{
				Namespace: namespace, WorkloadKind: kind, WorkloadName: name, Container: containerName,
				Image: image, Version: version, PodLabels: podLabels, Source: doc.Ref, WorkloadField: ".spec.template.spec.containers",
				Identity: identity, Instrumentation: instrumentation, Exporter: exporter,
				Propagation: propagation, Replicas: replicas,
			})
		}
	}
	return result
}

func collectScenarios(docs []document) []model.Scenario {
	var result []model.Scenario
	for _, doc := range docs {
		if !strings.EqualFold(stringValue(doc.Value, "type"), "Test") {
			continue
		}
		spec := mapValue(doc.Value, "spec")
		trigger := mapValue(spec, "trigger")
		if !strings.EqualFold(stringValue(trigger, "type"), "http") {
			continue
		}
		request := mapValue(trigger, "httpRequest")
		method := strings.ToUpper(strings.TrimSpace(stringValue(request, "method")))
		path := extractHTTPPath(stringValue(request, "url"))
		if method == "" || path == "" {
			continue
		}
		result = append(result, model.Scenario{ID: stringValue(spec, "id"), Method: method, Path: path, Source: doc.Ref})
	}
	return result
}

func resolveEnvironment(container map[string]any, namespace, workload string, labels, annotations map[string]string, configMaps map[string]map[string]string) map[string]resolvedValue {
	result := map[string]resolvedValue{}
	for _, raw := range sliceValue(container, "env") {
		item := asMap(raw)
		name := stringValue(item, "name")
		if name == "" {
			continue
		}
		if value, exists := item["value"]; exists {
			literal := fmt.Sprint(value)
			expanded, known := expandEnvironment(literal, result)
			result[name] = resolvedValue{Value: expanded, Known: known, Field: ".spec.template.spec.containers[].env[" + name + "]"}
			continue
		}
		valueFrom := mapValue(item, "valueFrom")
		if fieldRef := mapValue(valueFrom, "fieldRef"); len(fieldRef) > 0 {
			path := stringValue(fieldRef, "fieldPath")
			value, known := resolveField(path, namespace, workload, labels, annotations)
			result[name] = resolvedValue{Value: value, Known: known, Field: path}
			continue
		}
		if configRef := mapValue(valueFrom, "configMapKeyRef"); len(configRef) > 0 {
			mapName := stringValue(configRef, "name")
			key := stringValue(configRef, "key")
			value, known := configMaps[namespace+"/"+mapName][key]
			result[name] = resolvedValue{Value: value, Known: known, Field: "ConfigMap/" + mapName + ":" + key}
			continue
		}
		result[name] = resolvedValue{Known: false, Field: ".spec.template.spec.containers[].env[" + name + "]"}
	}
	// Kubernetes env expansion is ordered, but a short fixed-point pass also handles
	// values emitted by renderers in a different order without guessing unknowns.
	for pass := 0; pass < len(result); pass++ {
		changed := false
		for name, value := range result {
			if value.Known || value.Value == "" {
				continue
			}
			expanded, known := expandEnvironment(value.Value, result)
			if known {
				value.Value, value.Known = expanded, true
				result[name] = value
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return result
}

func identityFact(env map[string]resolvedValue, ref, container string) model.Fact {
	type candidate struct {
		value string
		known bool
		field string
	}
	var candidates []candidate
	if item, exists := env["OTEL_SERVICE_NAME"]; exists {
		candidates = append(candidates, candidate{strings.TrimSpace(item.Value), item.Known, item.Field})
	}
	if item, exists := env["OTEL_RESOURCE_ATTRIBUTES"]; exists {
		if item.Known {
			if value, ok := resourceAttributes(item.Value)["service.name"]; ok {
				candidates = append(candidates, candidate{strings.TrimSpace(value), true, item.Field + ".service.name"})
			}
		} else {
			candidates = append(candidates, candidate{"", false, item.Field + ".service.name"})
		}
	}
	evidence := make([]model.Evidence, 0, len(candidates))
	known := map[string]struct{}{}
	hasUnknown := false
	for _, item := range candidates {
		evidence = append(evidence, model.Evidence{Source: ref, Field: item.field})
		if !item.known || item.value == "" {
			hasUnknown = true
			continue
		}
		known[item.value] = struct{}{}
	}
	values := mapKeys(known)
	id := "container." + container + ".identity"
	switch {
	case len(values) > 1:
		return model.Fact{ID: id, Status: model.FactConflict, Value: strings.Join(values, ","), Message: "OpenTelemetry service identity has conflicting values", Evidence: evidence}
	case len(values) == 1:
		return model.Fact{ID: id, Status: model.FactConfirmed, Value: values[0], Message: "OpenTelemetry service identity is resolved", Evidence: evidence}
	case hasUnknown:
		return model.Fact{ID: id, Status: model.FactUnknown, Message: "OpenTelemetry service identity depends on unresolved configuration", Evidence: evidence}
	default:
		return model.Fact{ID: id, Status: model.FactAbsent, Message: "OpenTelemetry service identity is not declared", Evidence: []model.Evidence{{Source: ref, Field: ".spec.template.spec.containers[].env"}}}
	}
}

func instrumentationFact(env map[string]resolvedValue, annotations map[string]string, namespace string, instrumentations map[string]resolvedValue, ref, container string) (model.Fact, string) {
	id := "container." + container + ".instrumentation"
	if disabled, ok := env["OTEL_SDK_DISABLED"]; ok && disabled.Known && strings.EqualFold(strings.TrimSpace(disabled.Value), "true") {
		return model.Fact{ID: id, Status: model.FactAbsent, Message: "OpenTelemetry SDK is explicitly disabled", Evidence: []model.Evidence{{Source: ref, Field: disabled.Field}}}, ""
	}
	for key, value := range annotations {
		if !strings.HasPrefix(key, "instrumentation.opentelemetry.io/inject-") || strings.EqualFold(strings.TrimSpace(value), "false") {
			continue
		}
		name := strings.TrimSpace(value)
		if name == "" || strings.EqualFold(name, "true") {
			name = "default"
		}
		status := model.FactDeclared
		message := "OpenTelemetry auto-instrumentation injection is declared"
		if _, exists := instrumentations[namespace+"/"+name]; exists {
			status = model.FactConfirmed
			message = "OpenTelemetry auto-instrumentation references an available Instrumentation resource"
		}
		return model.Fact{ID: id, Status: status, Value: name, Message: message, Evidence: []model.Evidence{{Source: ref, Field: ".spec.template.metadata.annotations." + key}}}, name
	}
	for key, value := range env {
		if strings.HasPrefix(key, "OTEL_") && key != "OTEL_SDK_DISABLED" {
			return model.Fact{ID: id, Status: model.FactDeclared, Message: "OpenTelemetry runtime configuration is declared; SDK presence remains a runtime assumption", Evidence: []model.Evidence{{Source: ref, Field: value.Field}}}, ""
		}
	}
	return model.Fact{ID: id, Status: model.FactAbsent, Message: "No static OpenTelemetry instrumentation basis was found", Evidence: []model.Evidence{{Source: ref, Field: ".spec.template"}}}, ""
}

func exporterFact(env map[string]resolvedValue, injectionName, namespace string, instrumentations map[string]resolvedValue, services []KubernetesService, collectorConfigs map[string]bool, instrumentation model.Fact, ref, container string) model.Fact {
	id := "container." + container + ".exporter"
	if value, ok := env["OTEL_TRACES_EXPORTER"]; ok && value.Known && strings.EqualFold(strings.TrimSpace(value.Value), "none") {
		return model.Fact{ID: id, Status: model.FactAbsent, Message: "Trace exporter is explicitly disabled", Evidence: []model.Evidence{{Source: ref, Field: value.Field}}}
	}
	endpoint, exists := env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]
	if !exists {
		endpoint, exists = env["OTEL_EXPORTER_OTLP_ENDPOINT"]
	}
	if !exists && injectionName != "" {
		endpoint, exists = instrumentations[namespace+"/"+injectionName]
	}
	if !exists {
		if instrumentation.Status == model.FactAbsent {
			return model.Fact{ID: id, Status: model.FactAbsent, Message: "No trace exporter is declared with the missing instrumentation basis", Evidence: []model.Evidence{{Source: ref, Field: ".spec.template.spec.containers[].env"}}}
		}
		return model.Fact{ID: id, Status: model.FactUnknown, Message: "Trace exporter endpoint is not present in the supplied static artifacts", Evidence: []model.Evidence{{Source: ref, Field: ".spec.template.spec.containers[].env"}}}
	}
	if !endpoint.Known || strings.TrimSpace(endpoint.Value) == "" {
		return model.Fact{ID: id, Status: model.FactUnknown, Message: "Trace exporter endpoint cannot be resolved", Evidence: []model.Evidence{{Source: ref, Field: endpoint.Field}}}
	}
	status := model.FactDeclared
	message := "Trace exporter endpoint is declared; the destination pipeline is outside the supplied artifacts"
	host := endpointHost(endpoint.Value)
	if host != "" && hasCollectorService(namespace, host, services) && len(collectorConfigs) > 0 {
		status = model.FactConfirmed
		message = "Trace exporter resolves to a Kubernetes service and a Collector traces pipeline is present"
	}
	return model.Fact{ID: id, Status: status, Value: endpoint.Value, Message: message, Evidence: []model.Evidence{{Source: ref, Field: endpoint.Field}}}
}

func propagationFact(env map[string]resolvedValue, instrumentation model.Fact, ref, container string) model.Fact {
	id := "container." + container + ".propagation"
	if value, exists := env["OTEL_PROPAGATORS"]; exists {
		if !value.Known {
			return model.Fact{ID: id, Status: model.FactUnknown, Message: "HTTP propagators cannot be resolved", Evidence: []model.Evidence{{Source: ref, Field: value.Field}}}
		}
		for _, item := range strings.Split(strings.ToLower(value.Value), ",") {
			if strings.TrimSpace(item) == "tracecontext" {
				return model.Fact{ID: id, Status: model.FactConfirmed, Value: value.Value, Message: "W3C trace context propagation is configured", Evidence: []model.Evidence{{Source: ref, Field: value.Field}}}
			}
		}
		return model.Fact{ID: id, Status: model.FactAbsent, Value: value.Value, Message: "Configured propagators do not include W3C tracecontext", Evidence: []model.Evidence{{Source: ref, Field: value.Field}}}
	}
	if instrumentation.Status == model.FactConfirmed || instrumentation.Status == model.FactDeclared {
		return model.Fact{ID: id, Status: model.FactDeclared, Value: "tracecontext,baggage", Message: "OpenTelemetry default HTTP propagators are assumed because OTEL_PROPAGATORS is not overridden", Evidence: instrumentation.Evidence}
	}
	return model.Fact{ID: id, Status: model.FactUnknown, Message: "HTTP propagation cannot be assessed without an instrumentation basis", Evidence: []model.Evidence{{Source: ref, Field: ".spec.template"}}}
}

func replicaFact(kind string, spec map[string]any, ref string) model.Fact {
	id := "workload.replicas"
	if kind == "DaemonSet" {
		return model.Fact{ID: id, Status: model.FactUnknown, Message: "DaemonSet replica count depends on runtime node selection", Evidence: []model.Evidence{{Source: ref, Field: ".spec"}}}
	}
	value, exists := spec["replicas"]
	if !exists || value == nil {
		return model.Fact{ID: id, Status: model.FactConfirmed, Value: "1", Message: "Replica count uses the Kubernetes default", Evidence: []model.Evidence{{Source: ref, Field: ".spec.replicas(default=1)"}}}
	}
	count, ok := intValue(value)
	if !ok {
		return model.Fact{ID: id, Status: model.FactUnknown, Message: "Replica count cannot be resolved", Evidence: []model.Evidence{{Source: ref, Field: ".spec.replicas"}}}
	}
	if count <= 0 {
		return model.Fact{ID: id, Status: model.FactAbsent, Value: strconv.Itoa(count), Message: "Replica count must be positive for Bering handoff", Evidence: []model.Evidence{{Source: ref, Field: ".spec.replicas"}}}
	}
	return model.Fact{ID: id, Status: model.FactConfirmed, Value: strconv.Itoa(count), Message: "Replica count is resolved", Evidence: []model.Evidence{{Source: ref, Field: ".spec.replicas"}}}
}

func serviceVersion(env map[string]resolvedValue, image string) string {
	if value, exists := env["OTEL_RESOURCE_ATTRIBUTES"]; exists && value.Known {
		if version := strings.TrimSpace(resourceAttributes(value.Value)["service.version"]); version != "" {
			return version
		}
	}
	if index := strings.Index(image, "@sha256:"); index >= 0 {
		return image[index+1:]
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon > slash {
		return image[colon+1:]
	}
	return ""
}

func hasTracePipeline(raw string) bool {
	var value map[string]any
	if yaml.Unmarshal([]byte(raw), &value) != nil {
		return false
	}
	pipelines := mapValue(mapValue(value, "service"), "pipelines")
	traces := mapValue(pipelines, "traces")
	return len(traces) > 0 && len(sliceValue(traces, "exporters")) > 0
}

func hasCollectorService(namespace, host string, services []KubernetesService) bool {
	host = strings.TrimSuffix(host, ".")
	serviceName := strings.Split(host, ".")[0]
	for _, service := range services {
		if service.Namespace == namespace && service.Name == serviceName {
			return true
		}
	}
	return false
}

func endpointHost(value string) string {
	trimmed := strings.TrimSpace(value)
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return host
	}
	return strings.Split(trimmed, ":")[0]
}

func extractHTTPPath(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := url.Parse(value); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if scheme := strings.Index(value, "://"); scheme >= 0 {
		if slash := strings.Index(value[scheme+3:], "/"); slash >= 0 {
			return value[scheme+3+slash:]
		}
	}
	if strings.HasPrefix(value, "/") {
		return value
	}
	return ""
}

func resolveField(path, namespace, workload string, labels, annotations map[string]string) (string, bool) {
	switch strings.TrimSpace(path) {
	case "metadata.name":
		return workload, true
	case "metadata.namespace":
		return namespace, true
	}
	if key, ok := bracketKey(path, "metadata.labels"); ok {
		value, exists := labels[key]
		return value, exists
	}
	if key, ok := bracketKey(path, "metadata.annotations"); ok {
		value, exists := annotations[key]
		return value, exists
	}
	return "", false
}

func bracketKey(path, prefix string) (string, bool) {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, prefix+"[") || !strings.HasSuffix(path, "]") {
		return "", false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(path, prefix+"["), "]")
	value = strings.Trim(value, "'\"")
	return value, value != ""
}

func expandEnvironment(value string, env map[string]resolvedValue) (string, bool) {
	known := true
	expanded := envReferencePattern.ReplaceAllStringFunc(value, func(token string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(token, "$("), ")")
		item, exists := env[name]
		if !exists || !item.Known {
			known = false
			return token
		}
		return item.Value
	})
	return expanded, known
}

func resourceAttributes(value string) map[string]string {
	result := map[string]string{}
	for _, item := range strings.Split(value, ",") {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key != "" {
			result[key] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func namespaceOf(metadata map[string]any) string {
	if value := stringValue(metadata, "namespace"); value != "" {
		return value
	}
	return "default"
}

func mapValue(value map[string]any, key string) map[string]any { return asMap(value[key]) }

func asMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return map[string]any{}
}

func sliceValue(value map[string]any, key string) []any {
	result, _ := value[key].([]any)
	return result
}

func stringValue(value map[string]any, key string) string {
	if raw, exists := value[key]; exists && raw != nil {
		return strings.TrimSpace(fmt.Sprint(raw))
	}
	return ""
}

func stringMap(value map[string]any) map[string]string {
	result := map[string]string{}
	for key, raw := range value {
		if raw != nil {
			result[strings.TrimSpace(key)] = strings.TrimSpace(fmt.Sprint(raw))
		}
	}
	return result
}

func intValue(value any) (int, bool) {
	switch item := value.(type) {
	case int:
		return item, true
	case int64:
		return int(item), true
	case uint64:
		return int(item), true
	case float64:
		if item == float64(int(item)) {
			return int(item), true
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(item))
		return parsed, err == nil
	}
	return 0, false
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func MatchesSelector(labels, selector map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func RefMatches(ref, wanted string) bool {
	if strings.TrimSpace(wanted) == "" {
		return true
	}
	ref = strings.Split(filepath.ToSlash(ref), "#doc=")[0]
	cleanRef := strings.TrimSuffix(ref, filepath.Ext(ref))
	cleanWanted := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(wanted)), filepath.Ext(wanted))
	return strings.Contains(cleanRef, cleanWanted)
}
