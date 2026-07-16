package suite

import (
	"fmt"
	"slices"
	"strings"
)

// Cell is one matrix cell (server × client × transport) with the scenarios
// that apply to it, per the pairing and gating rules in harness/README.md.
type Cell struct {
	Transport string
	Server    *Entry
	Client    *Entry

	// Incompatible marks an empty spec intersection: an expected outcome
	// recorded in the matrix, never executed, never a failure.
	Incompatible bool

	Applicable []*Scenario
	Skipped    []SkippedScenario
}

// SkippedScenario is a scenario gated off by a missing server capability;
// reported, not failed.
type SkippedScenario struct {
	Scenario *Scenario
	Reason   string
}

// Name renders the cell for logs and failure details.
func (c *Cell) Name() string {
	return fmt.Sprintf("%s %s -> %s", c.Transport, c.Server.ID, c.Client.ID)
}

// ComputeGrid derives the full matrix: for each transport, every entry
// declaring a server on it pairs with every entry declaring a client on it.
func ComputeGrid(entries []*Entry, scenarios []*Scenario) []*Cell {
	var cells []*Cell
	for _, t := range Transports {
		for _, s := range entries {
			if s.Server == nil || !slices.Contains(s.Server.Transports, t) {
				continue
			}
			for _, c := range entries {
				if c.Client == nil || !slices.Contains(c.Client.Transports, t) {
					continue
				}
				cells = append(cells, newCell(t, s, c, scenarios))
			}
		}
	}
	return cells
}

func newCell(transport string, server, client *Entry, scenarios []*Scenario) *Cell {
	cell := &Cell{Transport: transport, Server: server, Client: client}
	if !specsIntersect(server.Spec, client.Spec) {
		cell.Incompatible = true
		return cell
	}
	for _, sc := range scenarios {
		if sc.Transport != "" && sc.Transport != transport {
			continue
		}
		if !slices.Contains(server.Server.Modes, sc.Mode) || !slices.Contains(client.Client.Modes, sc.Mode) {
			continue
		}
		if missing := missingFeatures(server.Server.Features, sc.Requires); len(missing) > 0 {
			cell.Skipped = append(cell.Skipped, SkippedScenario{
				Scenario: sc,
				Reason:   fmt.Sprintf("server %s lacks %s", server.ID, strings.Join(missing, ", ")),
			})
			continue
		}
		cell.Applicable = append(cell.Applicable, sc)
	}
	return cell
}

func specsIntersect(a, b []int) bool {
	for _, v := range a {
		if slices.Contains(b, v) {
			return true
		}
	}
	return false
}

func missingFeatures(features map[string]bool, requires []string) []string {
	var missing []string
	for _, req := range requires {
		if !features[req] {
			missing = append(missing, fmt.Sprintf("feature %q", req))
		}
	}
	return missing
}
