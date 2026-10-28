package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MB3R-Lab/Procrustes/internal/model"
)

func TestCLIEBPFCollectionHandoffWithoutSDK(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	goal := write("goal.yaml", `scope:
  namespaces: [default]
  services: [reader]
operation:
  id: read-items
  entry_service: reader
  method: GET
  path: /items
  mandatory_targets: [reader]
`)
	write("deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: reader
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels: {app: reader}
  template:
    metadata:
      labels: {app: reader}
    spec:
      containers:
        - name: reader
          image: example/reader:1
---
apiVersion: v1
kind: Service
metadata:
  name: reader
  namespace: default
spec:
  selector: {app: reader}
  ports:
    - port: 80
`)
	write("scenario.yaml", `type: Test
spec:
  id: read-items
  trigger:
    type: http
    httpRequest:
      method: GET
      url: http://reader/items
`)
	var stdout, stderr bytes.Buffer
	runner := New(&stdout, &stderr)
	out := filepath.Join(root, "preflight")
	code := runner.Run([]string{"analyze", "--source", "deployment=" + root, "--goal", goal,
		"--out-dir", out, "--collection-source", "ebpf-obi", "--source-domain", "deployment-a"})
	if code != 0 {
		t.Fatalf("CLI failed (%d): %s", code, stderr.String())
	}
	planRaw, err := os.ReadFile(filepath.Join(out, "collection-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan model.CollectionPlan
	if err := json.Unmarshal(planRaw, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Contract.Version != model.PlanContractVersionEBPF || len(plan.TraceSources) != 1 ||
		plan.TraceSources[0].BeringInput != "ebpf-obi" || plan.TraceSources[0].Domain != "deployment-a" {
		t.Fatalf("CLI did not emit the Bering source handoff: %+v", plan)
	}
	reportRaw, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report model.Report
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatal(err)
	}
	if report.GoalStatus != model.CapabilityPartial || len(report.Blockers) != 0 {
		t.Fatalf("unobserved OBI source was asserted ready or SDK-blocked: status=%s blockers=%+v", report.GoalStatus, report.Blockers)
	}
}
