package policy

import "reflect"

// RuleChange identifies the typed fields that differ for one rule ID.
type RuleChange struct {
	ID     string
	Fields []string
}

// RevisionDiff is a deterministic structural comparison of two compiled
// revisions. Runtime hit counters and timestamps are intentionally excluded.
type RevisionDiff struct {
	From         string
	To           string
	Added        []string
	Removed      []string
	Changed      []RuleChange
	Unchanged    []string
	OrderChanged bool
}

// Compare reports rule additions, removals, typed-field changes, and relative
// evaluation-order changes between two immutable revisions.
func Compare(from, to RuleSet) RevisionDiff {
	result := RevisionDiff{From: from.Revision(), To: to.Revision()}
	fromRules := from.Rules()
	toRules := to.Rules()
	fromByID := make(map[string]Rule, len(fromRules))
	toByID := make(map[string]Rule, len(toRules))
	for _, rule := range fromRules {
		fromByID[rule.ID] = rule
	}
	for _, rule := range toRules {
		toByID[rule.ID] = rule
	}

	for _, rule := range fromRules {
		next, ok := toByID[rule.ID]
		if !ok {
			result.Removed = append(result.Removed, rule.ID)
			continue
		}
		fields := changedRuleFields(rule, next)
		if len(fields) == 0 {
			result.Unchanged = append(result.Unchanged, rule.ID)
		} else {
			result.Changed = append(result.Changed, RuleChange{ID: rule.ID, Fields: fields})
		}
	}
	for _, rule := range toRules {
		if _, ok := fromByID[rule.ID]; !ok {
			result.Added = append(result.Added, rule.ID)
		}
	}

	fromOrder := make([]string, 0, len(fromRules))
	toOrder := make([]string, 0, len(toRules))
	for _, rule := range fromRules {
		if _, ok := toByID[rule.ID]; ok {
			fromOrder = append(fromOrder, rule.ID)
		}
	}
	for _, rule := range toRules {
		if _, ok := fromByID[rule.ID]; ok {
			toOrder = append(toOrder, rule.ID)
		}
	}
	result.OrderChanged = !reflect.DeepEqual(fromOrder, toOrder)
	return result
}

func changedRuleFields(from, to Rule) []string {
	var fields []string
	if from.Name != to.Name {
		fields = append(fields, "name")
	}
	if from.Priority != to.Priority {
		fields = append(fields, "priority")
	}
	if from.Enabled != to.Enabled {
		fields = append(fields, "enabled")
	}
	if from.Revision != to.Revision {
		fields = append(fields, "revision")
	}
	if !reflect.DeepEqual(from.Match, to.Match) {
		fields = append(fields, "match")
	}
	if !reflect.DeepEqual(from.Actions, to.Actions) {
		fields = append(fields, "actions")
	}
	if !reflect.DeepEqual(from.Transformations, to.Transformations) {
		fields = append(fields, "transformations")
	}
	if !reflect.DeepEqual(from.Metadata, to.Metadata) {
		fields = append(fields, "metadata")
	}
	return fields
}
