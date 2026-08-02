package policy

import (
	"reflect"
	"testing"
)

func TestCompareRevisionsReportsStructuralAndOrderChanges(t *testing.T) {
	from, err := Compile("before", []Rule{
		{ID: "changed", Name: "Old", Priority: 30, Enabled: true, Actions: []Action{{Kind: ActionAllow}}},
		{ID: "removed", Priority: 20, Enabled: true, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "stable", Priority: 10, Enabled: true, Actions: []Action{{Kind: ActionAllow}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	to, err := Compile("after", []Rule{
		{ID: "stable", Priority: 40, Enabled: true, Actions: []Action{{Kind: ActionAllow}}},
		{ID: "changed", Name: "New", Priority: 30, Enabled: false, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "added", Priority: 10, Enabled: true, Actions: []Action{{Kind: ActionAllow}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	diff := Compare(from, to)
	if diff.From != "before" || diff.To != "after" || !diff.OrderChanged {
		t.Fatalf("diff header = %#v", diff)
	}
	if !reflect.DeepEqual(diff.Added, []string{"added"}) || !reflect.DeepEqual(diff.Removed, []string{"removed"}) {
		t.Fatalf("added=%v removed=%v", diff.Added, diff.Removed)
	}
	if len(diff.Changed) != 2 || diff.Changed[0].ID != "changed" || !reflect.DeepEqual(diff.Changed[0].Fields, []string{"name", "enabled", "actions"}) || diff.Changed[1].ID != "stable" || !reflect.DeepEqual(diff.Changed[1].Fields, []string{"priority"}) {
		t.Fatalf("changed = %#v", diff.Changed)
	}
	if len(diff.Unchanged) != 0 {
		t.Fatalf("unchanged = %v", diff.Unchanged)
	}
}

func TestCompareRevisionsIgnoresRuntimeStatistics(t *testing.T) {
	fromRule := Rule{ID: "same", Enabled: true, Actions: []Action{{Kind: ActionAllow}}, HitCount: 1}
	toRule := fromRule
	toRule.HitCount = 99
	from, err := Compile("before", []Rule{fromRule})
	if err != nil {
		t.Fatal(err)
	}
	to, err := Compile("after", []Rule{toRule})
	if err != nil {
		t.Fatal(err)
	}
	diff := Compare(from, to)
	if len(diff.Changed) != 0 || !reflect.DeepEqual(diff.Unchanged, []string{"same"}) {
		t.Fatalf("diff = %#v", diff)
	}
}
