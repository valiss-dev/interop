package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// Conventions shared by all container runners. Runnables are invoked by
// absolute path because entry images may be distroless with no shell; the
// /usr/local/bin/<id>-{server,client} convention comes from the entry
// Dockerfiles. The fixture is bind-mounted read-only at /fixture, so
// scenario payloads must live under fixture/.
const (
	serverPort   = "8443"
	fixtureMount = "/fixture"
)

func imageTag(e *suite.Entry) string { return "valiss-interop-" + e.ID }

func serverBin(e *suite.Entry) string { return "/usr/local/bin/" + e.ID + "-server" }
func clientBin(e *suite.Entry) string { return "/usr/local/bin/" + e.ID + "-client" }

// serverCmd is the in-container server invocation for one (transport, mode).
func serverCmd(e *suite.Entry, transport, mode string) []string {
	return []string{
		serverBin(e),
		"--transport", transport,
		"--addr", "0.0.0.0:" + serverPort,
		"--operator", fixtureMount + "/operator.pub",
		"--allowlist", fixtureMount + "/allowlist.txt",
		"--mode", mode,
	}
}

// clientCmd is the in-container client invocation for one attempt.
func clientCmd(e *suite.Entry, call ClientCall) ([]string, error) {
	args := []string{
		clientBin(e),
		"--transport", call.Transport,
		"--addr", call.Addr,
		"--creds", fixtureMount + "/creds/" + call.Creds,
		"--mode", call.Mode,
	}
	if call.Nonce != "" {
		args = append(args, "--nonce", call.Nonce)
	}
	if call.Audience != "" {
		args = append(args, "--audience", call.Audience)
	}
	if call.Payload != "" {
		p, err := fixturePath(call.Payload)
		if err != nil {
			return nil, err
		}
		args = append(args, "--payload", p)
	}
	if call.TamperPayload != "" {
		p, err := fixturePath(call.TamperPayload)
		if err != nil {
			return nil, err
		}
		args = append(args, "--tamper-payload", p)
	}
	if call.TTL != "" {
		args = append(args, "--ttl", call.TTL)
	}
	if call.Chain != "" {
		args = append(args, "--chain", call.Chain)
	}
	return args, nil
}

// fixturePath maps a repo-root-relative fixture path to its in-container
// mount; container runners mount only the fixture.
func fixturePath(p string) (string, error) {
	rel, found := strings.CutPrefix(p, "fixture/")
	if !found {
		return "", fmt.Errorf("payload %q is outside fixture/: container runners mount only the fixture", p)
	}
	return fixtureMount + "/" + rel, nil
}

// runCmd executes one CLI invocation, returning stdout and folding stderr
// into the error.
func runCmd(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w\n%s", bin, strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// awaitReady polls a container's stdout for the contract's "ready <addr>"
// line, bailing out early when the container dies.
func awaitReady(ctx context.Context, logs func(context.Context) ([]byte, error), running func(context.Context) (bool, error)) error {
	deadline := time.Now().Add(readyTimeout)
	for {
		out, err := logs(ctx)
		if err != nil {
			return fmt.Errorf("read logs: %w", err)
		}
		for line := range bytes.Lines(out) {
			if bytes.HasPrefix(line, []byte("ready ")) {
				return nil
			}
		}
		if up, err := running(ctx); err == nil && !up {
			return fmt.Errorf("container exited before reporting readiness")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("did not report readiness in time")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// tailLines keeps error output readable: image build logs run long.
func tailLines(out []byte, n int) []byte {
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return bytes.Join(lines, []byte("\n"))
}
