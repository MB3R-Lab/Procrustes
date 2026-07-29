package model

const (
	GoalContractName       = "io.mb3r.procrustes.goal"
	GoalContractVersion    = "0.1.0"
	ReportContractName     = "io.mb3r.procrustes.report"
	ReportContractVersion  = "0.1.0"
	PlanContractName       = "io.mb3r.procrustes.collection-plan"
	PlanContractVersion    = "0.1.0"
	ToolVersion            = "0.1.0"
	CapabilityInventory    = "service_inventory"
	CapabilityTopology     = "candidate_topology"
	CapabilityOperation    = "operation_specific_model"
	CapabilityReplicaAware = "replica_aware_model"
)

type Contract struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type Goal struct {
	Contract  Contract  `json:"contract" yaml:"contract"`
	Scope     Scope     `json:"scope" yaml:"scope"`
	Operation Operation `json:"operation" yaml:"operation"`
}

type Scope struct {
	Namespaces []string `json:"namespaces" yaml:"namespaces"`
	Services   []string `json:"services" yaml:"services"`
}

type Operation struct {
	ID               string   `json:"id" yaml:"id"`
	EntryService     string   `json:"entry_service" yaml:"entry_service"`
	Method           string   `json:"method" yaml:"method"`
	Path             string   `json:"path" yaml:"path"`
	MandatoryTargets []string `json:"mandatory_targets" yaml:"mandatory_targets"`
	ScenarioRef      string   `json:"scenario_ref,omitempty" yaml:"scenario_ref,omitempty"`
}

type FactStatus string

const (
	FactConfirmed FactStatus = "CONFIRMED"
	FactDeclared  FactStatus = "DECLARED"
	FactUnknown   FactStatus = "UNKNOWN"
	FactAbsent    FactStatus = "ABSENT"
	FactConflict  FactStatus = "CONFLICT"
)

type CapabilityStatus string

const (
	CapabilityExpected    CapabilityStatus = "EXPECTED"
	CapabilityPartial     CapabilityStatus = "PARTIAL"
	CapabilityBlocked     CapabilityStatus = "BLOCKED"
	CapabilityNotAssessed CapabilityStatus = "NOT_ASSESSED"
)

type Source struct {
	Alias string `json:"alias"`
	Path  string `json:"-"`
}

type Evidence struct {
	Source string `json:"source"`
	Field  string `json:"field,omitempty"`
}

type Fact struct {
	ID       string     `json:"id"`
	Status   FactStatus `json:"status"`
	Value    string     `json:"value,omitempty"`
	Message  string     `json:"message"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

type ServiceAssessment struct {
	ID              string `json:"id"`
	Namespace       string `json:"namespace,omitempty"`
	Workload        string `json:"workload,omitempty"`
	Container       string `json:"container,omitempty"`
	Image           string `json:"image,omitempty"`
	Version         string `json:"version,omitempty"`
	DeploymentEntry string `json:"deployment_entry,omitempty"`

	WorkloadEvidence Fact `json:"workload_evidence"`
	Identity         Fact `json:"identity"`
	Instrumentation  Fact `json:"instrumentation"`
	Exporter         Fact `json:"exporter"`
	Propagation      Fact `json:"propagation"`
	Replicas         Fact `json:"replicas"`
}

type Capability struct {
	ID          string           `json:"id"`
	Status      CapabilityStatus `json:"status"`
	Basis       []string         `json:"basis"`
	Limitations []string         `json:"limitations,omitempty"`
	Blockers    []string         `json:"blockers,omitempty"`
}

type Finding struct {
	RuleID     string     `json:"rule_id"`
	Status     FactStatus `json:"status"`
	Service    string     `json:"service,omitempty"`
	Capability string     `json:"capability"`
	Message    string     `json:"message"`
	Evidence   []Evidence `json:"evidence,omitempty"`
	Action     string     `json:"action"`
	Owner      string     `json:"owner"`
	CanNarrow  bool       `json:"can_narrow_scope"`
}

type Scenario struct {
	ID     string `json:"id,omitempty"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Source string `json:"source"`
}

type TraceSystem struct {
	System   string     `json:"system"`
	Role     string     `json:"role"`
	Service  string     `json:"service,omitempty"`
	Status   FactStatus `json:"status"`
	Message  string     `json:"message"`
	Evidence []Evidence `json:"evidence"`
}

type TraceCollection struct {
	System          string     `json:"system"`
	Collection      string     `json:"collection"`
	BeringInput     string     `json:"bering_input"`
	AdapterRequired bool       `json:"adapter_required"`
	Evidence        []Evidence `json:"evidence,omitempty"`
}

type CollectionPlan struct {
	Contract                   Contract          `json:"contract"`
	Operation                  Operation         `json:"operation"`
	ExpectedServices           []string          `json:"expected_services"`
	Scenarios                  []Scenario        `json:"scenarios"`
	TraceSources               []TraceCollection `json:"trace_sources,omitempty"`
	RequiredResourceAttributes []string          `json:"required_resource_attributes"`
	RecommendedAttributes      []string          `json:"recommended_resource_attributes"`
	KnownLimitations           []string          `json:"known_limitations,omitempty"`
	BeringOverlay              string            `json:"bering_overlay"`
}

type Report struct {
	Contract       Contract            `json:"contract"`
	ToolVersion    string              `json:"tool_version"`
	Fingerprint    string              `json:"fingerprint"`
	Goal           Goal                `json:"goal"`
	Sources        []string            `json:"sources"`
	GoalStatus     CapabilityStatus    `json:"goal_status"`
	Services       []ServiceAssessment `json:"services"`
	TraceSystems   []TraceSystem       `json:"trace_systems,omitempty"`
	OperationFacts []Fact              `json:"operation_facts"`
	Capabilities   []Capability        `json:"capabilities"`
	Blockers       []Finding           `json:"blockers,omitempty"`
	Remediation    []Finding           `json:"remediation,omitempty"`
	CollectionPlan CollectionPlan      `json:"collection_plan"`
	Limitations    []string            `json:"limitations"`
}
