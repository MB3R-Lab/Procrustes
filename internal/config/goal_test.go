package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoalDefaultsAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goal.yaml")
	raw := []byte("scope:\n  services: [frontend, checkout]\noperation:\n  id: checkout\n  entry_service: frontend\n  method: get\n  path: checkout\n  mandatory_targets: [checkout]\n")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	goal, _, err := LoadGoal(path)
	if err != nil {
		t.Fatal(err)
	}
	if goal.Operation.Method != "GET" || goal.Operation.Path != "/checkout" {
		t.Fatalf("operation was not normalized: %+v", goal.Operation)
	}
	if len(goal.Scope.Namespaces) != 1 || goal.Scope.Namespaces[0] != "default" {
		t.Fatalf("unexpected namespace defaults: %+v", goal.Scope.Namespaces)
	}
}
