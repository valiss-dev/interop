// Package matrix executes the grid of cells through a runner, judges the
// client-reported outcomes against the scenario expectations, and renders
// the reports.
package matrix

import (
	"context"
	"fmt"
	"log"
	"slices"

	"github.com/valiss-dev/interop/orchestrator/internal/runner"
	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// Cell and scenario statuses as they appear in reports.
const (
	statusPass         = "pass"
	statusFail         = "fail"
	statusSkip         = "skip"
	statusIncompatible = "incompatible"
)

// Result is the machine report (--report) and the source of the human
// rendering.
type Result struct {
	Runner  string        `json:"runner"`
	Cells   []*CellResult `json:"cells"`
	Summary Summary       `json:"summary"`
}

// CellResult records one executed (or incompatible) cell.
type CellResult struct {
	Transport string           `json:"transport"`
	Server    string           `json:"server"`
	Client    string           `json:"client"`
	Status    string           `json:"status"`
	Errors    []string         `json:"errors,omitempty"`
	Scenarios []ScenarioResult `json:"scenarios,omitempty"`
}

// ScenarioResult records one scenario in one cell.
type ScenarioResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Summary aggregates the matrix outcome; the process exits nonzero iff
// CellsFailed > 0.
type Summary struct {
	CellsPassed       int `json:"cells_passed"`
	CellsFailed       int `json:"cells_failed"`
	CellsIncompatible int `json:"cells_incompatible"`
	ScenariosPassed   int `json:"scenarios_passed"`
	ScenariosFailed   int `json:"scenarios_failed"`
	ScenariosSkipped  int `json:"scenarios_skipped"`
}

// Failed reports whether any applicable scenario (or cell infrastructure)
// failed.
func (r *Result) Failed() bool { return r.Summary.CellsFailed > 0 }

// Execute runs every cell through the runner. Entries are prepared lazily,
// once each; a preparation failure fails every cell that needs the entry
// without aborting the rest of the matrix.
func Execute(ctx context.Context, r runner.Runner, runnerName string, cells []*suite.Cell) *Result {
	res := &Result{Runner: runnerName}
	prepared := map[string]error{}
	prepare := func(e *suite.Entry) error {
		if err, ok := prepared[e.ID]; ok {
			return err
		}
		log.Printf("prepare %s", e.ID)
		err := r.Prepare(ctx, e)
		if err != nil {
			log.Printf("prepare %s: %v", e.ID, err)
		}
		prepared[e.ID] = err
		return err
	}

	for _, cell := range cells {
		cr := runCell(ctx, r, prepare, cell)
		res.Cells = append(res.Cells, cr)
		res.Summary.add(cr)
	}
	return res
}

func (s *Summary) add(cr *CellResult) {
	switch cr.Status {
	case statusIncompatible:
		s.CellsIncompatible++
	case statusFail:
		s.CellsFailed++
	default:
		s.CellsPassed++
	}
	for _, sr := range cr.Scenarios {
		switch sr.Status {
		case statusPass:
			s.ScenariosPassed++
		case statusFail:
			s.ScenariosFailed++
		case statusSkip:
			s.ScenariosSkipped++
		}
	}
}

func runCell(ctx context.Context, r runner.Runner, prepare func(*suite.Entry) error, cell *suite.Cell) *CellResult {
	cr := &CellResult{Transport: cell.Transport, Server: cell.Server.ID, Client: cell.Client.ID}
	if cell.Incompatible {
		cr.Status = statusIncompatible
		return cr
	}
	for _, sk := range cell.Skipped {
		cr.Scenarios = append(cr.Scenarios, ScenarioResult{ID: sk.Scenario.ID, Status: statusSkip, Detail: sk.Reason})
	}
	if len(cell.Applicable) > 0 {
		if err := prepareCell(prepare, cell); err != nil {
			for _, sc := range cell.Applicable {
				cr.Scenarios = append(cr.Scenarios, ScenarioResult{ID: sc.ID, Status: statusFail, Detail: "not run: " + err.Error()})
			}
		} else {
			log.Printf("cell %s: %d scenarios", cell.Name(), len(cell.Applicable))
			runCellModes(ctx, r, cell, cr)
		}
	}
	cr.Status = statusPass
	if len(cr.Errors) > 0 || slices.ContainsFunc(cr.Scenarios, func(sr ScenarioResult) bool { return sr.Status == statusFail }) {
		cr.Status = statusFail
	}
	return cr
}

func prepareCell(prepare func(*suite.Entry) error, cell *suite.Cell) error {
	if err := prepare(cell.Server); err != nil {
		return err
	}
	if cell.Client.ID != cell.Server.ID {
		return prepare(cell.Client)
	}
	return nil
}

// runCellModes groups the cell's scenarios by mode so the server starts once
// per (cell, mode), and appends the executed results.
func runCellModes(ctx context.Context, r runner.Runner, cell *suite.Cell, cr *CellResult) {
	for _, mode := range suite.Modes {
		var group []*suite.Scenario
		for _, sc := range cell.Applicable {
			if sc.Mode == mode {
				group = append(group, sc)
			}
		}
		if len(group) == 0 {
			continue
		}
		srv, err := r.StartServer(ctx, cell.Server, cell.Transport, mode)
		if err != nil {
			for _, sc := range group {
				cr.Scenarios = append(cr.Scenarios, ScenarioResult{ID: sc.ID, Status: statusFail, Detail: "not run: " + err.Error()})
			}
			continue
		}
		for _, sc := range group {
			cr.Scenarios = append(cr.Scenarios, runScenario(ctx, r, cell, sc, srv.Addr()))
		}
		if err := srv.Stop(); err != nil {
			cr.Errors = append(cr.Errors, fmt.Sprintf("server %s (%s/%s): %v", cell.Server.ID, cell.Transport, mode, err))
		}
	}
}

// runScenario performs the scenario's attempts with identical arguments:
// with repeat=N, attempts 1..N-1 must be accepted and the expectation
// (expect_last) judges attempt N.
func runScenario(ctx context.Context, r runner.Runner, cell *suite.Cell, sc *suite.Scenario, addr string) ScenarioResult {
	call := runner.ClientCall{
		Transport: cell.Transport,
		Addr:      addr,
		Mode:      sc.Mode,
		Creds:     sc.Creds,
		Nonce:     sc.Nonce,
		Audience:  sc.Audience,
		Payload:   sc.Payload,
	}
	n := sc.Attempts()
	for i := 1; i <= n; i++ {
		out, err := r.RunClient(ctx, cell.Client, call)
		if err == nil {
			if i < n {
				err = judgeWarmup(cell.Transport, out)
			} else {
				err = judgeFinal(cell.Transport, sc.Want(), out)
			}
		}
		if err != nil {
			detail := err.Error()
			if n > 1 {
				detail = fmt.Sprintf("attempt %d/%d: %s", i, n, detail)
			}
			return ScenarioResult{ID: sc.ID, Status: statusFail, Detail: detail}
		}
	}
	return ScenarioResult{ID: sc.ID, Status: statusPass}
}
