package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// cliEngine drives a docker-CLI-compatible engine: docker itself or podman,
// whose CLI mirrors docker for every subcommand used here. Servers and
// clients join a per-run bridge network and reach each other by container
// name.
type cliEngine struct {
	bin     string
	paths   Paths
	network string
	images  map[string]string
	seq     int
}

func newCLIEngine(ctx context.Context, bin string, paths Paths) (*cliEngine, error) {
	if _, err := exec.CommandContext(ctx, bin, "version").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s unavailable: %v; start it or use another --runner", bin, err)
	}
	r := &cliEngine{
		bin:     bin,
		paths:   paths,
		network: fmt.Sprintf("valiss-interop-%d", os.Getpid()),
		images:  map[string]string{},
	}
	if out, err := runCmd(ctx, bin, "network", "create", r.network); err != nil {
		return nil, fmt.Errorf("create network: %w\n%s", err, out)
	}
	return r, nil
}

func (r *cliEngine) Prepare(ctx context.Context, e *suite.Entry) error {
	if _, ok := r.images[e.ID]; ok {
		return nil
	}
	tag := imageTag(e)
	cmd := exec.CommandContext(ctx, r.bin, "build",
		"-t", tag,
		"-f", filepath.Join(e.Dir, e.Build.Dockerfile),
		e.Dir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s build %s: %w\n%s", r.bin, e.ID, err, tailLines(out, 40))
	}
	r.images[e.ID] = tag
	return nil
}

func (r *cliEngine) StartServer(ctx context.Context, e *suite.Entry, transport, mode string) (Server, error) {
	image, ok := r.images[e.ID]
	if !ok {
		return nil, fmt.Errorf("entry %s not prepared", e.ID)
	}
	r.seq++
	name := fmt.Sprintf("%s-s%d", r.network, r.seq)
	args := append([]string{
		"run", "--detach",
		"--name", name,
		"--network", r.network,
		"-v", r.paths.Fixture + ":" + fixtureMount + ":ro",
		image,
	}, serverCmd(e, transport, mode)...)
	if out, err := runCmd(ctx, r.bin, args...); err != nil {
		return nil, fmt.Errorf("run server %s (%s/%s): %w\n%s", e.ID, transport, mode, err, out)
	}
	err := awaitReady(ctx,
		func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, r.bin, "logs", name).Output()
		},
		func(ctx context.Context) (bool, error) {
			out, err := exec.CommandContext(ctx, r.bin, "inspect", "-f", "{{.State.Running}}", name).Output()
			return strings.TrimSpace(string(out)) == "true", err
		},
	)
	if err != nil {
		logs, _ := exec.Command(r.bin, "logs", name).CombinedOutput()
		_ = exec.Command(r.bin, "rm", "-f", name).Run()
		return nil, fmt.Errorf("server %s (%s/%s): %w\n%s", e.ID, transport, mode, err, logs)
	}
	return &cliEngineServer{bin: r.bin, name: name, addr: name + ":" + serverPort}, nil
}

func (r *cliEngine) RunClient(ctx context.Context, e *suite.Entry, call ClientCall) (Outcome, error) {
	image, ok := r.images[e.ID]
	if !ok {
		return Outcome{}, fmt.Errorf("entry %s not prepared", e.ID)
	}
	cmd, err := clientCmd(e, call)
	if err != nil {
		return Outcome{}, err
	}
	args := append([]string{
		"run", "--rm",
		"--network", r.network,
		"-v", r.paths.Fixture + ":" + fixtureMount + ":ro",
		image,
	}, cmd...)
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	out, err := runCmd(ctx, r.bin, args...)
	if err != nil {
		return Outcome{}, fmt.Errorf("client %s: %w", e.ID, err)
	}
	return ParseOutcome(out)
}

func (r *cliEngine) Close() error {
	if out, err := runCmd(context.Background(), r.bin, "network", "rm", r.network); err != nil {
		return fmt.Errorf("remove network: %w\n%s", err, out)
	}
	return nil
}

type cliEngineServer struct {
	bin  string
	name string
	addr string
}

func (s *cliEngineServer) Addr() string { return s.addr }

// Stop terminates the container: `stop` delivers SIGTERM and only escalates
// to SIGKILL after its grace period, so a zero exit code proves the
// contract's clean-SIGTERM-exit requirement.
func (s *cliEngineServer) Stop() error {
	defer func() { _ = exec.Command(s.bin, "rm", "-f", s.name).Run() }()
	if out, err := runCmd(context.Background(), s.bin, "stop", s.name); err != nil {
		return fmt.Errorf("stop server container: %w\n%s", err, out)
	}
	code, err := exec.Command(s.bin, "inspect", "-f", "{{.State.ExitCode}}", s.name).Output()
	if err != nil {
		return fmt.Errorf("inspect server container: %w", err)
	}
	if c := strings.TrimSpace(string(code)); c != "0" {
		logs, _ := exec.Command(s.bin, "logs", s.name).CombinedOutput()
		return fmt.Errorf("server did not exit cleanly on SIGTERM (exit %s)\n%s", c, logs)
	}
	return nil
}
