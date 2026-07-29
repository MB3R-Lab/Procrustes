package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MB3R-Lab/Procrustes/internal/model"
	"gopkg.in/yaml.v3"
)

func LoadGoal(path string) (model.Goal, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.Goal{}, nil, fmt.Errorf("read goal: %w", err)
	}
	var goal model.Goal
	decErr := yaml.Unmarshal(raw, &goal)
	if decErr != nil {
		return model.Goal{}, nil, fmt.Errorf("decode goal yaml: %w", decErr)
	}
	normalizeGoal(&goal)
	if err := validateGoal(goal); err != nil {
		return model.Goal{}, nil, err
	}
	return goal, raw, nil
}

func normalizeGoal(goal *model.Goal) {
	goal.Contract.Name = strings.TrimSpace(goal.Contract.Name)
	goal.Contract.Version = strings.TrimSpace(goal.Contract.Version)
	if goal.Contract.Name == "" {
		goal.Contract.Name = model.GoalContractName
	}
	if goal.Contract.Version == "" {
		goal.Contract.Version = model.GoalContractVersion
	}
	goal.Scope.Namespaces = normalizeUnique(goal.Scope.Namespaces, false)
	if len(goal.Scope.Namespaces) == 0 {
		goal.Scope.Namespaces = []string{"default"}
	}
	goal.Scope.Services = normalizeUnique(goal.Scope.Services, true)
	goal.Operation.ID = strings.TrimSpace(goal.Operation.ID)
	goal.Operation.EntryService = strings.TrimSpace(goal.Operation.EntryService)
	goal.Operation.Method = strings.ToUpper(strings.TrimSpace(goal.Operation.Method))
	goal.Operation.Path = normalizeHTTPPath(goal.Operation.Path)
	goal.Operation.MandatoryTargets = normalizeUnique(goal.Operation.MandatoryTargets, true)
	goal.Operation.ScenarioRef = filepath.ToSlash(filepath.Clean(strings.TrimSpace(goal.Operation.ScenarioRef)))
	if goal.Operation.ScenarioRef == "." {
		goal.Operation.ScenarioRef = ""
	}
}

func validateGoal(goal model.Goal) error {
	if goal.Contract.Name != model.GoalContractName || goal.Contract.Version != model.GoalContractVersion {
		return fmt.Errorf("unsupported goal contract %s@%s", goal.Contract.Name, goal.Contract.Version)
	}
	if len(goal.Scope.Services) == 0 {
		return errors.New("goal scope.services must contain at least one service")
	}
	if goal.Operation.ID == "" || goal.Operation.EntryService == "" || goal.Operation.Method == "" || goal.Operation.Path == "" {
		return errors.New("goal operation requires id, entry_service, method, and path")
	}
	if len(goal.Operation.MandatoryTargets) == 0 {
		return errors.New("goal operation.mandatory_targets must contain at least one service")
	}
	serviceSet := make(map[string]struct{}, len(goal.Scope.Services))
	for _, service := range goal.Scope.Services {
		serviceSet[service] = struct{}{}
	}
	if _, ok := serviceSet[goal.Operation.EntryService]; !ok {
		return fmt.Errorf("operation entry_service %q is not in scope.services", goal.Operation.EntryService)
	}
	for _, target := range goal.Operation.MandatoryTargets {
		if _, ok := serviceSet[target]; !ok {
			return fmt.Errorf("operation mandatory target %q is not in scope.services", target)
		}
	}
	return nil
}

func normalizeUnique(values []string, sortValues bool) []string {
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
	if sortValues {
		sort.Strings(result)
	}
	return result
}

func normalizeHTTPPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "/") {
		return value
	}
	return "/" + value
}
