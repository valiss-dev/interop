// Package runner executes harness entry runnables in the contract's canonical
// container mode: one image per entry, the fixture bind-mounted read-only.
// Engines: docker, podman (CLI-compatible), and Apple's container CLI.
package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

const (
	// readyTimeout bounds the wait for the contract's "ready <addr>" line;
	// generous because a container may cold-start.
	readyTimeout = 30 * time.Second

	// stopTimeout bounds the wait for a clean SIGTERM exit; container
	// engines wait several seconds themselves before escalating to KILL.
	stopTimeout = 15 * time.Second

	// clientTimeout bounds one client invocation.
	clientTimeout = 60 * time.Second
)

// Paths locates the repo material the runners need.
type Paths struct {
	Root    string // repo root; scenario payload paths resolve against it
	Fixture string
}

// ClientCall carries one scenario attempt in runner-neutral terms: creds by
// fixture file name and payload by repo-root-relative path, so each runner
// resolves them for its own filesystem view.
type ClientCall struct {
	Transport     string
	Addr          string
	Mode          string
	Creds         string
	Nonce         string
	Audience      string
	Payload       string
	TTL           string
	TamperPayload string
	Chain         string
}

// Runner executes entry runnables.
type Runner interface {
	// Prepare builds an entry's runnables; called once per entry before
	// any StartServer/RunClient use of it.
	Prepare(ctx context.Context, e *suite.Entry) error

	// StartServer starts the entry's server for one (transport, mode) and
	// returns once it reported readiness.
	StartServer(ctx context.Context, e *suite.Entry, transport, mode string) (Server, error)

	// RunClient performs one client attempt and parses its outcome line.
	RunClient(ctx context.Context, e *suite.Entry, call ClientCall) (Outcome, error)

	// Close releases runner-wide resources (temp binaries, networks).
	Close() error
}

// Server is a running harness server. Addr is the address clients dial;
// Stop terminates it via SIGTERM and errors on an unclean exit, which the
// contract treats as a failure.
type Server interface {
	Addr() string
	Stop() error
}

// New builds the runner selected by name.
func New(ctx context.Context, name string, paths Paths) (Runner, error) {
	switch name {
	case "docker", "podman":
		return newCLIEngine(ctx, name, paths)
	case "apple":
		return newApple(ctx, paths)
	default:
		return nil, fmt.Errorf("unknown runner %q (docker, podman, or apple)", name)
	}
}
