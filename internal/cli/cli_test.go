package cli

import (
	"strings"
	"testing"

	"github.com/samaasi/lazy-chat/internal/models"
)

func TestSplitNPreservesTheRemainderVerbatim(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want []string
	}{
		{"bob hello   world  ", 2, []string{"bob", "hello   world"}},
		{"bob", 2, []string{"bob"}},
		{"", 2, nil},
		{"  a   b   c  d ", 3, []string{"a", "b", "c  d"}},
		{"one", 1, []string{"one"}},
		{"tab\tseparated\ttext", 2, []string{"tab", "separated\ttext"}},
	}
	for _, c := range cases {
		got := splitN(c.in, c.n)
		if strings.Join(got, "|") != strings.Join(c.want, "|") || len(got) != len(c.want) {
			t.Errorf("splitN(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestParseCount(t *testing.T) {
	for in, want := range map[string]int{"": defaultCount, "5": 5, "100000": maxCount} {
		if got, err := parseCount(in); err != nil || got != want {
			t.Errorf("parseCount(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"0", "-3", "x", "1.5"} {
		if _, err := parseCount(bad); err == nil {
			t.Errorf("parseCount(%q) accepted", bad)
		}
	}
}

func TestPickGroup(t *testing.T) {
	groups := []*models.Group{
		{ID: "grp_aaaa1111", Name: "Crew"},
		{ID: "grp_aaaa2222", Name: "Ops"},
		{ID: "grp_bbbb3333", Name: "ops"},
	}
	pick := func(q string) (string, error) {
		g, err := pickGroup(q, groups, func(g *models.Group) (string, string) { return g.ID, g.Name })
		if err != nil {
			return "", err
		}
		return g.ID, nil
	}
	for q, want := range map[string]string{
		"grp_aaaa1111": "grp_aaaa1111", // exact ID
		"GRP_AAAA1111": "grp_aaaa1111", // case-insensitive
		"grp_bbbb":     "grp_bbbb3333", // unique prefix
		"crew":         "grp_aaaa1111", // name
	} {
		if got, err := pick(q); err != nil || got != want {
			t.Errorf("pick(%q) = %q, %v; want %q", q, got, err, want)
		}
	}
	for _, q := range []string{"grp_aaaa", "ops", "nope", "grp", ""} {
		if got, err := pick(q); err == nil {
			t.Errorf("pick(%q) = %q; ambiguous or unknown queries must fail", q, got)
		}
	}
}
