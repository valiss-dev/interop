package matrix

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// WriteGitHub emits the GitHub Actions integration: a Markdown job summary
// appended to $GITHUB_STEP_SUMMARY and one ::error:: annotation per failure on
// stdout. Outside a workflow (no GITHUB_STEP_SUMMARY) it is a no-op, so main
// can call it unconditionally.
func WriteGitHub(res *Result) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open step summary: %w", err)
	}
	defer f.Close()
	githubSummary(f, res)
	githubAnnotations(os.Stdout, res)
	return nil
}

// githubSummary renders the job-summary Markdown: one table per transport,
// failure and skip details, and the totals line.
func githubSummary(w io.Writer, res *Result) {
	fmt.Fprintf(w, "## Interop matrix — runner: %s\n", res.Runner)
	for _, t := range suite.Transports {
		cells := cellsFor(res, t)
		if len(cells) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n### %s\n\n", t)
		githubTable(w, cells)
	}

	s := res.Summary
	fmt.Fprintf(w, "\n**Scenarios:** %d passed · %d failed · %d skipped — **Cells:** %d passed · %d failed · %d incompatible\n",
		s.ScenariosPassed, s.ScenariosFailed, s.ScenariosSkipped,
		s.CellsPassed, s.CellsFailed, s.CellsIncompatible)

	failures, skips := collectDetails(res)
	if len(failures) > 0 {
		fmt.Fprintf(w, "\n### Failures\n\n")
		for _, l := range failures {
			fmt.Fprintf(w, "- `%s`\n", l)
		}
	}
	if len(skips) > 0 {
		fmt.Fprintf(w, "\n<details><summary>Skipped (%d)</summary>\n\n", len(skips))
		for _, l := range skips {
			fmt.Fprintf(w, "- `%s`\n", l)
		}
		fmt.Fprintf(w, "\n</details>\n")
	}
}

func githubTable(w io.Writer, cells []*CellResult) {
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
			return "—"
		case c.Status == statusPass:
			return "✅ pass"
		case c.Status == statusFail:
			return "❌ **fail**"
		case c.Status == statusIncompatible:
			return "⚪ incompatible"
		default:
			return c.Status
		}
	}

	fmt.Fprintf(w, "| server \\ client |")
	for _, cl := range clients {
		fmt.Fprintf(w, " `%s` |", cl)
	}
	fmt.Fprintf(w, "\n|---|%s\n", strings.Repeat("---|", len(clients)))
	for _, srv := range servers {
		fmt.Fprintf(w, "| `%s` |", srv)
		for _, cl := range clients {
			fmt.Fprintf(w, " %s |", display(byPair[[2]string{srv, cl}]))
		}
		fmt.Fprintln(w)
	}
}

// githubAnnotations emits one ::error:: workflow command per failure, so
// failures surface on the run page and the PR without opening the log.
func githubAnnotations(w io.Writer, res *Result) {
	failures, _ := collectDetails(res)
	for _, l := range failures {
		fmt.Fprintf(w, "::error title=interop matrix::%s\n", escapeAnnotation(l))
	}
}

// collectDetails flattens failure and skip lines the way the plain renderer
// shows them, one "<transport> <server> -> <client> :: <detail>" per entry.
func collectDetails(res *Result) (failures, skips []string) {
	for _, c := range res.Cells {
		cell := fmt.Sprintf("%s %s -> %s", c.Transport, c.Server, c.Client)
		for _, e := range c.Errors {
			failures = append(failures, fmt.Sprintf("%s :: %s", cell, e))
		}
		for _, sr := range c.Scenarios {
			switch sr.Status {
			case statusFail:
				failures = append(failures, fmt.Sprintf("%s :: %s: %s", cell, sr.ID, sr.Detail))
			case statusSkip:
				skips = append(skips, fmt.Sprintf("%s :: %s (%s)", cell, sr.ID, sr.Detail))
			}
		}
	}
	return failures, skips
}

// escapeAnnotation escapes the message data of a workflow command per the
// GitHub Actions runner rules.
func escapeAnnotation(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}
