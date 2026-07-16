// Command orchestrator runs the valiss interop matrix (CONTRACT.md): it
// derives the (server × client × transport) grid from the harness manifests,
// executes every applicable scenario of scenarios.yaml in each cell through
// the selected runner, judges the client-reported outcomes, and reports the
// matrix. It exits nonzero iff an applicable scenario failed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/valiss-dev/interop/orchestrator/internal/matrix"
	"github.com/valiss-dev/interop/orchestrator/internal/runner"
	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

var errMatrixFailed = errors.New("matrix failed")

func main() {
	log.SetFlags(0)
	log.SetPrefix("orchestrator: ")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, errMatrixFailed) {
			os.Exit(1)
		}
		log.Fatal(err)
	}
}

type options struct {
	runner        string
	root          string
	scenarios     string
	harnessDir    string
	fixtureDir    string
	onlyTransport string
	onlyCell      string
	report        string
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	var opts options
	fs := flag.NewFlagSet("orchestrator", flag.ContinueOnError)
	fs.StringVar(&opts.runner, "runner", "local", "runner: local, docker, podman, or apple")
	fs.StringVar(&opts.root, "root", "", "repo root (default: nearest parent of cwd with scenarios.yaml)")
	fs.StringVar(&opts.scenarios, "scenarios", "", "scenarios file (default: <root>/scenarios.yaml)")
	fs.StringVar(&opts.harnessDir, "harness-dir", "", "harness entries directory (default: <root>/harness)")
	fs.StringVar(&opts.fixtureDir, "fixture-dir", "", "fixture directory (default: <root>/fixture)")
	fs.StringVar(&opts.onlyTransport, "only-transport", "", "run one transport: http or grpc")
	fs.StringVar(&opts.onlyCell, "only-cell", "", "run one cell, as server:client entry ids")
	fs.StringVar(&opts.report, "report", "", "write the machine JSON report to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	paths, harnessDir, scenariosPath, err := resolvePaths(&opts)
	if err != nil {
		return err
	}
	scenarios, err := suite.LoadScenarios(scenariosPath)
	if err != nil {
		return err
	}
	if err := checkFixture(paths, scenarios); err != nil {
		return err
	}
	entries, err := suite.DiscoverEntries(harnessDir)
	if err != nil {
		return err
	}

	cells := suite.ComputeGrid(entries, scenarios)
	cells, err = filterCells(cells, entries, &opts)
	if err != nil {
		return err
	}
	if len(cells) == 0 {
		return errors.New("no cells match the given filters")
	}

	r, err := runner.New(ctx, opts.runner, paths)
	if err != nil {
		return err
	}
	res := matrix.Execute(ctx, r, opts.runner, cells)
	if err := r.Close(); err != nil {
		log.Printf("runner close: %v", err)
	}

	matrix.Render(stdout, res)
	if opts.report != "" {
		if err := matrix.WriteJSON(opts.report, res); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		log.Printf("report written to %s", opts.report)
	}
	if res.Failed() {
		return errMatrixFailed
	}
	return nil
}

func resolvePaths(opts *options) (paths runner.Paths, harnessDir, scenariosPath string, err error) {
	root, err := findRoot(opts.root)
	if err != nil {
		return runner.Paths{}, "", "", err
	}
	paths = runner.Paths{
		Root:    root,
		Fixture: orDefault(opts.fixtureDir, filepath.Join(root, "fixture")),
	}
	harnessDir = orDefault(opts.harnessDir, filepath.Join(root, "harness"))
	scenariosPath = orDefault(opts.scenarios, filepath.Join(root, "scenarios.yaml"))
	return paths, harnessDir, scenariosPath, nil
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// findRoot locates the repo root: an explicit --root, else the nearest
// parent of the cwd holding scenarios.yaml, else (for odd cwds) the parent
// of this source file's directory.
func findRoot(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	if cwd, err := os.Getwd(); err == nil {
		for dir := cwd; ; {
			if _, err := os.Stat(filepath.Join(dir, "scenarios.yaml")); err == nil {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		dir := filepath.Dir(filepath.Dir(file))
		if _, err := os.Stat(filepath.Join(dir, "scenarios.yaml")); err == nil {
			return dir, nil
		}
	}
	return "", errors.New("repo root not found (no scenarios.yaml above cwd); pass --root")
}

// checkFixture fails fast on missing fixture material instead of failing
// scenario by scenario.
func checkFixture(paths runner.Paths, scenarios []*suite.Scenario) error {
	if _, err := os.Stat(filepath.Join(paths.Fixture, "operator.pub")); err != nil {
		return fmt.Errorf("fixture not found at %s (operator.pub missing)", paths.Fixture)
	}
	for _, sc := range scenarios {
		if _, err := os.Stat(filepath.Join(paths.Fixture, "creds", sc.Creds)); err != nil {
			return fmt.Errorf("scenario %s: creds %s not in fixture", sc.ID, sc.Creds)
		}
		if sc.Payload != "" {
			if _, err := os.Stat(filepath.Join(paths.Root, filepath.FromSlash(sc.Payload))); err != nil {
				return fmt.Errorf("scenario %s: payload %s not found", sc.ID, sc.Payload)
			}
		}
	}
	return nil
}

func filterCells(cells []*suite.Cell, entries []*suite.Entry, opts *options) ([]*suite.Cell, error) {
	if opts.onlyTransport != "" {
		if !slices.Contains(suite.Transports, opts.onlyTransport) {
			return nil, fmt.Errorf("unknown transport %q", opts.onlyTransport)
		}
		cells = slices.DeleteFunc(slices.Clone(cells), func(c *suite.Cell) bool {
			return c.Transport != opts.onlyTransport
		})
	}
	if opts.onlyCell != "" {
		server, client, ok := strings.Cut(opts.onlyCell, ":")
		if !ok {
			return nil, fmt.Errorf("--only-cell wants server:client, got %q", opts.onlyCell)
		}
		for _, id := range []string{server, client} {
			if !slices.ContainsFunc(entries, func(e *suite.Entry) bool { return e.ID == id }) {
				return nil, fmt.Errorf("--only-cell: no entry %q", id)
			}
		}
		cells = slices.DeleteFunc(slices.Clone(cells), func(c *suite.Cell) bool {
			return c.Server.ID != server || c.Client.ID != client
		})
	}
	return cells, nil
}
