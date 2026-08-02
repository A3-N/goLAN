package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"golan/internal/policy"
	workproject "golan/internal/project"
)

func (m *Model) attachProject(project *workproject.Project) {
	m.clearLiveEvidence()
	m.clearObservedSecrets()
	m.networkTracker = nil
	m.networkSessionPersisted = ""
	m.selectedNetworkDevice = ""
	m.networkSection = 0
	m.project = project
	m.projectSessions = nil
	m.projectSessionErr = ""
	m.policyStore = &policy.Store{}
	if project == nil {
		return
	}
	m.restoreLatestNetworkSession()
	m.refreshAssociatedSessions()
	active := project.Manifest().Preferences.ActivePolicyRevision
	if active == "" {
		return
	}
	if _, err := m.ensurePolicyRevision(active); err != nil {
		m.print("project warn: restore active policy: " + err.Error())
		return
	}
	if err := m.policyStore.ActivateRevision(active); err != nil {
		m.print("project warn: restore active policy: " + err.Error())
		return
	}
	m.print("policy: restored " + active)
}

func (m *Model) allowProjectSwitch() bool {
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("project err: cannot switch project while " + blocker)
		return false
	}
	if pending := m.pendingRuntimeOperation(); pending != "" {
		m.print("project err: cannot switch project while " + pending)
		return false
	}
	return true
}

func (m *Model) ensurePolicyRevision(revision string) (policy.RuleSet, error) {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return policy.RuleSet{}, fmt.Errorf("policy revision is required")
	}
	if retained, ok := m.policyStore.Revision(revision); ok {
		return retained, nil
	}
	if m.project == nil {
		return policy.RuleSet{}, fmt.Errorf("policy revision %q is not retained", revision)
	}
	content, _, err := m.project.ReadPolicyRevision(revision)
	if err != nil {
		return policy.RuleSet{}, err
	}
	rules, err := decodePolicyRules(content)
	if err != nil {
		return policy.RuleSet{}, fmt.Errorf("policy revision %q: %w", revision, err)
	}
	if err := m.policyStore.Register(revision, rules); err != nil {
		return policy.RuleSet{}, err
	}
	retained, _ := m.policyStore.Revision(revision)
	return retained, nil
}

func decodePolicyRules(content []byte) ([]policy.Rule, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var rules []policy.Rule
	if err := decoder.Decode(&rules); err != nil {
		return nil, fmt.Errorf("decode policy JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return nil, fmt.Errorf("decode policy JSON: %w", err)
	}
	for _, rule := range rules {
		if rule.HitCount != 0 || rule.LastMatch != nil {
			return nil, fmt.Errorf("hit_count and last_match are runtime-only")
		}
	}
	return rules, nil
}

func (m *Model) showPolicyHistory() {
	history := m.policyStore.History()
	active := ""
	if revision, ok := m.policyStore.Active(); ok {
		active = revision.Revision()
	}
	retained := make(map[string]policy.RevisionSummary, len(history))
	for _, revision := range history {
		retained[revision.Revision] = revision
	}

	type historyRow struct {
		revision string
		name     string
		created  string
		project  bool
	}
	var rows []historyRow
	seen := make(map[string]bool)
	if m.project != nil {
		manifest := m.project.Manifest()
		policies := append([]workproject.PolicyRevision(nil), manifest.Policies...)
		sort.SliceStable(policies, func(i, j int) bool { return policies[i].CreatedAt.After(policies[j].CreatedAt) })
		for _, record := range policies {
			rows = append(rows, historyRow{revision: record.Revision, name: record.Name, created: record.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), project: true})
			seen[record.Revision] = true
		}
	}
	for _, revision := range history {
		if !seen[revision.Revision] {
			rows = append(rows, historyRow{revision: revision.Revision})
		}
	}
	if len(rows) == 0 {
		m.print("policy history: none")
		return
	}
	m.print(fmt.Sprintf("policy history: active=%s revisions=%d", emptyLabel(active, "none"), len(rows)))
	for _, row := range rows {
		marker := " "
		if row.revision == active {
			marker = "*"
		}
		detail := "not loaded"
		if summary, ok := retained[row.revision]; ok {
			detail = fmt.Sprintf("rules=%d retained", summary.RuleCount)
		}
		if row.project {
			detail += " project"
		}
		if row.name != "" {
			detail += " name=" + row.name
		}
		if row.created != "" {
			detail += " created=" + row.created
		}
		m.print(fmt.Sprintf("  %s %s %s", marker, row.revision, detail))
	}
}

func (m *Model) showPolicyComparison(fromName, toName string) {
	from, err := m.ensurePolicyRevision(fromName)
	if err != nil {
		m.print("policy err: compare " + err.Error())
		return
	}
	to, err := m.ensurePolicyRevision(toName)
	if err != nil {
		m.print("policy err: compare " + err.Error())
		return
	}
	diff := policy.Compare(from, to)
	m.print(fmt.Sprintf("policy compare: %s -> %s", diff.From, diff.To))
	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Changed) == 0 && !diff.OrderChanged {
		m.print(fmt.Sprintf("  identical typed rules (%d unchanged)", len(diff.Unchanged)))
		return
	}
	if len(diff.Added) > 0 {
		m.print("  added: " + strings.Join(diff.Added, ","))
	}
	if len(diff.Removed) > 0 {
		m.print("  removed: " + strings.Join(diff.Removed, ","))
	}
	for _, change := range diff.Changed {
		m.print(fmt.Sprintf("  changed %s: %s", change.ID, strings.Join(change.Fields, ",")))
	}
	if diff.OrderChanged {
		m.print("  evaluation order: changed")
	}
	if len(diff.Unchanged) > 0 {
		m.print(fmt.Sprintf("  unchanged: %d", len(diff.Unchanged)))
	}
}

func (m *Model) rollbackPolicy(revision string) {
	target, err := m.ensurePolicyRevision(revision)
	if err != nil {
		m.print("policy err: rollback " + err.Error())
		return
	}
	if m.project != nil {
		found := false
		for _, record := range m.project.Manifest().Policies {
			if record.Revision == target.Revision() {
				found = true
				break
			}
		}
		if !found {
			m.print(fmt.Sprintf("policy err: rollback revision %q is not indexed in the active project", target.Revision()))
			return
		}
	}
	if err := m.applyPolicyToRuntime(target.Revision(), target.Rules()); err != nil {
		m.print("policy err: rollback " + err.Error())
		return
	}
	if err := m.policyStore.ActivateRevision(target.Revision()); err != nil {
		m.print("policy err: rollback " + err.Error())
		return
	}
	if m.project != nil {
		if err := m.project.SetActivePolicyRevision(target.Revision()); err != nil {
			m.print("policy err: rollback " + err.Error())
			return
		}
	}
	m.workspace = workspaceRules
	suffix := ""
	if m.project != nil {
		suffix = " (PROJECT*)"
	}
	m.print("policy: rolled back to " + target.Revision() + suffix)
}

func (m *Model) applyPolicyToRuntime(revision string, rules []policy.Rule) error {
	switch {
	case m.edgeSession != nil:
		return m.edgeSession.SetPolicy(revision, rules)
	case m.bridge != nil:
		return m.bridge.SetPolicy(revision, rules)
	case m.listener != nil:
		return m.listener.SetPolicy(revision, rules)
	default:
		return nil
	}
}

func (m Model) policyRevisionNames() []string {
	seen := make(map[string]bool)
	var result []string
	for _, revision := range m.policyStore.History() {
		seen[revision.Revision] = true
		result = append(result, revision.Revision)
	}
	if m.project != nil {
		for _, revision := range m.project.Manifest().Policies {
			if !seen[revision.Revision] {
				seen[revision.Revision] = true
				result = append(result, revision.Revision)
			}
		}
	}
	sort.Strings(result)
	return result
}

func emptyLabel(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
