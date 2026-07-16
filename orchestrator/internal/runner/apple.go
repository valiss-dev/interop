package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// apple drives Apple's `container` CLI (macOS containerization). It differs
// from the docker-compatible engines: there are no user-defined networks, so
// containers reach each other by the IP each gets on the default vmnet; and
// a stopped container exposes no exit code, so a successful `container stop`
// is taken as the clean SIGTERM exit.
type apple struct {
	paths  Paths
	images map[string]string
	seq    int
	pid    int
}

func newApple(ctx context.Context, paths Paths) (*apple, error) {
	if out, err := exec.CommandContext(ctx, "container", "system", "status").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("apple container system unavailable: %v\n%s\nrun `container system start` or use another --runner", err, tailLines(out, 5))
	}
	return &apple{paths: paths, images: map[string]string{}, pid: os.Getpid()}, nil
}

func (r *apple) Prepare(ctx context.Context, e *suite.Entry) error {
	if _, ok := r.images[e.ID]; ok {
		return nil
	}
	tag := imageTag(e)
	cmd := exec.CommandContext(ctx, "container", "build",
		"--progress", "plain",
		"-t", tag,
		"-f", filepath.Join(e.Dir, e.Build.Dockerfile),
		e.Dir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("container build %s: %w\n%s", e.ID, err, tailLines(out, 40))
	}
	r.images[e.ID] = tag
	return nil
}

func (r *apple) StartServer(ctx context.Context, e *suite.Entry, transport, mode string) (Server, error) {
	image, ok := r.images[e.ID]
	if !ok {
		return nil, fmt.Errorf("entry %s not prepared", e.ID)
	}
	r.seq++
	name := fmt.Sprintf("valiss-interop-%d-s%d", r.pid, r.seq)
	args := append([]string{
		"run", "--detach",
		"--progress", "none",
		"--name", name,
		"-v", r.paths.Fixture + ":" + fixtureMount + ":ro",
		image,
	}, serverCmd(e, transport, mode)...)
	if out, err := runCmd(ctx, "container", args...); err != nil {
		return nil, fmt.Errorf("run server %s (%s/%s): %w\n%s", e.ID, transport, mode, err, out)
	}
	fail := func(err error) (Server, error) {
		logs, _ := exec.Command("container", "logs", name).CombinedOutput()
		_ = exec.Command("container", "rm", "-f", name).Run()
		return nil, fmt.Errorf("server %s (%s/%s): %w\n%s", e.ID, transport, mode, err, logs)
	}
	err := awaitReady(ctx,
		func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "container", "logs", name).Output()
		},
		func(ctx context.Context) (bool, error) {
			st, err := inspectApple(ctx, name)
			return err == nil && st.State == "running", err
		},
	)
	if err != nil {
		return fail(err)
	}
	st, err := inspectApple(ctx, name)
	if err != nil {
		return fail(err)
	}
	ip := st.ipv4()
	if ip == "" {
		return fail(fmt.Errorf("container has no ipv4 address"))
	}
	return &appleServer{name: name, addr: ip + ":" + serverPort}, nil
}

func (r *apple) RunClient(ctx context.Context, e *suite.Entry, call ClientCall) (Outcome, error) {
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
		"--progress", "none",
		"-v", r.paths.Fixture + ":" + fixtureMount + ":ro",
		image,
	}, cmd...)
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	out, err := runCmd(ctx, "container", args...)
	if err != nil {
		return Outcome{}, fmt.Errorf("client %s: %w", e.ID, err)
	}
	return ParseOutcome(out)
}

func (r *apple) Close() error { return nil }

type appleServer struct {
	name string
	addr string
}

func (s *appleServer) Addr() string { return s.addr }

func (s *appleServer) Stop() error {
	defer func() { _ = exec.Command("container", "rm", "-f", s.name).Run() }()
	if out, err := runCmd(context.Background(), "container", "stop", s.name); err != nil {
		return fmt.Errorf("stop server container: %w\n%s", err, out)
	}
	return nil
}

// appleStatus is the slice of `container inspect` JSON the runner reads.
type appleStatus struct {
	State    string `json:"state"`
	Networks []struct {
		IPv4Address string `json:"ipv4Address"`
	} `json:"networks"`
}

// ipv4 returns the container's address with the CIDR suffix stripped.
func (st *appleStatus) ipv4() string {
	for _, n := range st.Networks {
		if n.IPv4Address != "" {
			addr, _, _ := strings.Cut(n.IPv4Address, "/")
			return addr
		}
	}
	return ""
}

func inspectApple(ctx context.Context, name string) (*appleStatus, error) {
	out, err := runCmd(ctx, "container", "inspect", name)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Status appleStatus `json:"status"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse container inspect: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("container %s not found", name)
	}
	return &entries[0].Status, nil
}
