package matrix

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// Render prints the human summary: one matrix table per transport, then
// failure details, skips, and the totals line.
func Render(w io.Writer, res *Result) {
	fmt.Fprintf(w, "interop matrix (runner: %s)\n", res.Runner)
	for _, t := range suite.Transports {
		cells := cellsFor(res, t)
		if len(cells) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", t)
		renderTable(w, cells)
	}
	renderDetails(w, res)
	s := res.Summary
	fmt.Fprintf(w, "\nscenarios: %d passed, %d failed, %d skipped; cells: %d passed, %d failed, %d incompatible\n",
		s.ScenariosPassed, s.ScenariosFailed, s.ScenariosSkipped,
		s.CellsPassed, s.CellsFailed, s.CellsIncompatible)
}

func cellsFor(res *Result, transport string) []*CellResult {
	var cells []*CellResult
	for _, c := range res.Cells {
		if c.Transport == transport {
			cells = append(cells, c)
		}
	}
	return cells
}

func renderTable(w io.Writer, cells []*CellResult) {
	var servers, clients []string
	byPair := map[[2]string]*CellResult{}
	for _, c := range cells {
		if !slices.Contains(servers, c.Server) {
			servers = append(servers, c.Server)
		}
		if !slices.Contains(clients, c.Client) {
			clients = append(clients, c.Client)
		}
		byPair[[2]string{c.Server, c.Client}] = c
	}

	display := func(c *CellResult) string {
		switch {
		case c == nil:
			return "-"
		case c.Status == statusFail:
			return "FAIL"
		default:
			return c.Status
		}
	}

	head := "server \\ client"
	rowWidth := len(head)
	for _, s := range servers {
		rowWidth = max(rowWidth, len(s))
	}
	colWidths := make([]int, len(clients))
	for i, cl := range clients {
		colWidths[i] = len(cl)
		for _, srv := range servers {
			colWidths[i] = max(colWidths[i], len(display(byPair[[2]string{srv, cl}])))
		}
	}

	row := func(first string, cols []string) {
		fmt.Fprintf(w, "  %-*s", rowWidth, first)
		for i, c := range cols {
			fmt.Fprintf(w, " | %-*s", colWidths[i], c)
		}
		fmt.Fprintln(w)
	}
	row(head, clients)
	for _, srv := range servers {
		cols := make([]string, len(clients))
		for i, cl := range clients {
			cols[i] = display(byPair[[2]string{srv, cl}])
		}
		row(srv, cols)
	}
}

func renderDetails(w io.Writer, res *Result) {
	failures, skips := collectDetails(res)
	if len(failures) > 0 {
		fmt.Fprintf(w, "\nfailures:\n  %s\n", strings.Join(failures, "\n  "))
	}
	if len(skips) > 0 {
		fmt.Fprintf(w, "\nskipped:\n  %s\n", strings.Join(skips, "\n  "))
	}
}

// WriteJSON writes the machine report for --report.
func WriteJSON(path string, res *Result) error {
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
