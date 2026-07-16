package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// local builds each entry's ./cmd/server and ./cmd/client with the host Go
// toolchain and runs them as plain processes. It only handles entries that
// are Go modules; other languages go through a container runner.
type local struct {
	paths  Paths
	binDir string
	bins   map[string]localBins
}

type localBins struct {
	server string
	client string
}

func newLocal(paths Paths) (*local, error) {
	binDir, err := os.MkdirTemp("", "valiss-interop-*")
	if err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	return &local{paths: paths, binDir: binDir, bins: map[string]localBins{}}, nil
}

func (r *local) Prepare(ctx context.Context, e *suite.Entry) error {
	if _, ok := r.bins[e.ID]; ok {
		return nil
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "go.mod")); err != nil {
		return fmt.Errorf("entry %s is not a Go module (no go.mod): the local runner builds Go entries only, use a container runner", e.ID)
	}
	b := localBins{
		server: filepath.Join(r.binDir, e.ID+"-server"),
		client: filepath.Join(r.binDir, e.ID+"-client"),
	}
	for bin, pkg := range map[string]string{b.server: "./cmd/server", b.client: "./cmd/client"} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, pkg)
		cmd.Dir = e.Dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("build %s %s: %w\n%s", e.ID, pkg, err, out)
		}
	}
	r.bins[e.ID] = b
	return nil
}

func (r *local) StartServer(ctx context.Context, e *suite.Entry, transport, mode string) (Server, error) {
	b, ok := r.bins[e.ID]
	if !ok {
		return nil, fmt.Errorf("entry %s not prepared", e.ID)
	}
	cmd := exec.Command(b.server,
		"--transport", transport,
		"--addr", "127.0.0.1:0",
		"--operator", filepath.Join(r.paths.Fixture, "operator.pub"),
		"--allowlist", filepath.Join(r.paths.Fixture, "allowlist.txt"),
		"--mode", mode,
	)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start server %s: %w", e.ID, err)
	}

	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		}
		close(ready)
	}()

	fail := func(cause string) (Server, error) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("server %s (%s/%s): %s\n%s", e.ID, transport, mode, cause, stderr.Bytes())
	}
	select {
	case line, ok := <-ready:
		if !ok || !strings.HasPrefix(line, "ready ") {
			return fail(fmt.Sprintf("did not report readiness, got %q", line))
		}
		// The pipe must keep draining or a chatty server would block.
		go func() { _, _ = io.Copy(io.Discard, stdout) }()
		return &localServer{cmd: cmd, addr: strings.TrimPrefix(line, "ready "), stderr: stderr}, nil
	case <-time.After(readyTimeout):
		return fail("did not report readiness in time")
	case <-ctx.Done():
		return fail(ctx.Err().Error())
	}
}

func (r *local) RunClient(ctx context.Context, e *suite.Entry, call ClientCall) (Outcome, error) {
	b, ok := r.bins[e.ID]
	if !ok {
		return Outcome{}, fmt.Errorf("entry %s not prepared", e.ID)
	}
	args := []string{
		"--transport", call.Transport,
		"--addr", call.Addr,
		"--creds", filepath.Join(r.paths.Fixture, "creds", call.Creds),
		"--mode", call.Mode,
	}
	if call.Nonce != "" {
		args = append(args, "--nonce", call.Nonce)
	}
	if call.Audience != "" {
		args = append(args, "--audience", call.Audience)
	}
	if call.Payload != "" {
		args = append(args, "--payload", filepath.Join(r.paths.Root, filepath.FromSlash(call.Payload)))
	}
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.client, args...)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	out, err := cmd.Output()
	if err != nil {
		return Outcome{}, fmt.Errorf("client %s: %w\n%s", e.ID, err, stderr.Bytes())
	}
	return ParseOutcome(out)
}

func (r *local) Close() error {
	return os.RemoveAll(r.binDir)
}

type localServer struct {
	cmd    *exec.Cmd
	addr   string
	stderr *bytes.Buffer
}

func (s *localServer) Addr() string { return s.addr }

func (s *localServer) Stop() error {
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal server: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("server did not exit cleanly on SIGTERM: %w\n%s", err, s.stderr.Bytes())
		}
		return nil
	case <-time.After(stopTimeout):
		_ = s.cmd.Process.Kill()
		<-done
		return errors.New("server did not exit after SIGTERM within timeout")
	}
}
