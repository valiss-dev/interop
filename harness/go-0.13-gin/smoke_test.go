// Package smoke proves the go-0.13-gin harness end-to-end without
// containers: it builds this entry's server and the go-0.12 reference
// client (the known-good driver, like the orchestrator pairs entries),
// starts the server against the committed fixture, and drives every
// scenarios.yaml scenario over HTTP in both modes, asserting the contract
// outcomes (CONTRACT.md) including the §7 reason codes on rejection and the
// chain-negotiation signal on bare message tokens.
package smoke

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// outcome mirrors the client's one-line report.
type outcome struct {
	Status        any              `json:"status"`
	Reason        *string          `json:"reason"`
	Identity      *outcomeIdentity `json:"identity"`
	ChainRequired bool             `json:"chain_required"`
}

type outcomeIdentity struct {
	Tenant string  `json:"tenant"`
	User   *string `json:"user"`
}

// bins builds this entry's server and the go-0.12 reference client once per
// test binary. The client comes from the sibling entry so the driving side
// of every smoke run is the same known-good implementation the matrix
// itself pairs servers with.
func bins(t *testing.T) (server, client string) {
	t.Helper()
	dir := t.TempDir()
	server = filepath.Join(dir, "server")
	client = filepath.Join(dir, "client")

	build := exec.Command("go", "build", "-o", server, "./cmd/server")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build ./cmd/server: %v\n%s", err, out)
	}

	clientDir, err := filepath.Abs(filepath.Join("..", "go-0.12"))
	if err != nil {
		t.Fatal(err)
	}
	build = exec.Command("go", "build", "-o", client, "./cmd/client")
	build.Dir = clientDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build go-0.12 client: %v\n%s", err, out)
	}
	return server, client
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "operator.pub")); err != nil {
		t.Fatalf("fixture not found (run fixture/gen): %v", err)
	}
	return dir
}

// startServer launches the harness server, waits for its readiness line, and
// registers a cleanup that SIGTERMs it and asserts a clean exit.
func startServer(t *testing.T, bin, mode string) (addr string) {
	t.Helper()
	fixture := fixtureDir(t)
	cmd := exec.Command(bin,
		"--transport", "http",
		"--addr", "127.0.0.1:0",
		"--operator", filepath.Join(fixture, "operator.pub"),
		"--allowlist", filepath.Join(fixture, "allowlist.txt"),
		"--mode", mode,
	)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		}
		close(ready)
	}()
	select {
	case line, ok := <-ready:
		if !ok || !strings.HasPrefix(line, "ready ") {
			t.Fatalf("server did not report readiness, got %q", line)
		}
		addr = strings.TrimPrefix(line, "ready ")
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("server did not report readiness in time")
	}

	t.Cleanup(func() {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Errorf("signal server: %v", err)
			return
		}
		if err := cmd.Wait(); err != nil {
			t.Errorf("server did not exit cleanly on SIGTERM: %v", err)
		}
	})
	return addr
}

// runClient invokes the reference client once and parses its outcome line.
// The client must exit 0 whether the request was accepted or rejected.
func runClient(t *testing.T, bin string, args ...string) outcome {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("client %v: %v", args, err)
	}
	var out outcome
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("client output %q: %v", raw, err)
	}
	return out
}

// wantAccept asserts the accept outcome: HTTP 200, no reason, and the
// expected identity.
func wantAccept(t *testing.T, out outcome, tenant string, user *string) {
	t.Helper()
	wantStatus(t, out, 200)
	if out.Reason != nil {
		t.Errorf("accept carried reason %q", *out.Reason)
	}
	if out.Identity == nil {
		t.Fatal("accept carried no identity")
	}
	if out.Identity.Tenant != tenant {
		t.Errorf("tenant = %q, want %q", out.Identity.Tenant, tenant)
	}
	switch {
	case user == nil && out.Identity.User != nil:
		t.Errorf("user = %q, want null", *out.Identity.User)
	case user != nil && (out.Identity.User == nil || *out.Identity.User != *user):
		t.Errorf("user = %v, want %q", out.Identity.User, *user)
	}
}

// wantReject asserts the reject outcome: HTTP 401, the expected §7 reason,
// and no identity.
func wantReject(t *testing.T, out outcome, reason string) {
	t.Helper()
	wantStatus(t, out, 401)
	if out.Reason == nil || *out.Reason != reason {
		t.Errorf("reason = %v, want %q", out.Reason, reason)
	}
	if out.Identity != nil {
		t.Errorf("reject carried identity %+v", out.Identity)
	}
}

func wantStatus(t *testing.T, out outcome, want int) {
	t.Helper()
	got, ok := out.Status.(float64)
	if !ok || int(got) != want {
		t.Errorf("status = %v, want %d", out.Status, want)
	}
}

func strp(s string) *string { return &s }

func TestSigned(t *testing.T) {
	server, client := bins(t)
	fixture := fixtureDir(t)

	addr := startServer(t, server, "signed")
	call := func(creds string, extra ...string) outcome {
		args := append([]string{
			"--transport", "http", "--addr", addr,
			"--creds", filepath.Join(fixture, "creds", creds),
		}, extra...)
		return runClient(t, client, args...)
	}

	t.Run("account-valid", func(t *testing.T) {
		wantAccept(t, call("account.creds"), "acme", nil)
	})
	t.Run("user-valid", func(t *testing.T) {
		wantAccept(t, call("user.creds"), "acme", strp("alice"))
	})
	t.Run("bearer-valid", func(t *testing.T) {
		wantAccept(t, call("bearer.creds"), "acme", strp("alice"))
	})
	t.Run("account-revoked", func(t *testing.T) {
		wantReject(t, call("revoked.creds"), "not_allowlisted")
	})
	t.Run("expired", func(t *testing.T) {
		wantReject(t, call("expired.creds"), "expired")
	})
	t.Run("wrong-key", func(t *testing.T) {
		wantReject(t, call("wrongkey.creds"), "bad_request_signature")
	})
	t.Run("replay", func(t *testing.T) {
		const nonce = "interop-nonce-http"
		wantAccept(t, call("user.creds", "--nonce", nonce), "acme", strp("alice"))
		wantReject(t, call("user.creds", "--nonce", nonce), "replay")
	})
}

func TestMessage(t *testing.T) {
	server, client := bins(t)
	fixture := fixtureDir(t)
	const sink = "interop://sink"

	addr := startServer(t, server, "message")
	call := func(creds, audience string, extra ...string) outcome {
		args := append([]string{
			"--transport", "http", "--addr", addr,
			"--creds", filepath.Join(fixture, "creds", creds),
			"--mode", "message",
			"--audience", audience,
			"--payload", filepath.Join(fixture, "payloads", "hello.bin"),
		}, extra...)
		return runClient(t, client, args...)
	}

	t.Run("valid", func(t *testing.T) {
		out := call("user.creds", sink)
		wantAccept(t, out, "acme", strp("alice"))
		if out.ChainRequired {
			t.Error("accept carried the chain-required signal")
		}
	})
	t.Run("wrong-audience", func(t *testing.T) {
		wantReject(t, call("user.creds", "interop://other"), "wrong_audience")
	})
	t.Run("revoked-chain", func(t *testing.T) {
		wantReject(t, call("revoked.creds", sink), "not_allowlisted")
	})
	t.Run("checksum-mismatch", func(t *testing.T) {
		out := call("user.creds", sink,
			"--tamper-payload", filepath.Join(fixture, "payloads", "tampered.bin"))
		wantReject(t, out, "checksum_mismatch")
	})
	t.Run("expired", func(t *testing.T) {
		wantReject(t, call("user.creds", sink, "--ttl", "-5m"), "expired")
	})
	t.Run("detached-chain", func(t *testing.T) {
		out := call("user.creds", sink, "--chain", "detached")
		wantAccept(t, out, "acme", strp("alice"))
	})
	t.Run("bare-signals-negotiation", func(t *testing.T) {
		out := call("user.creds", sink, "--chain", "none")
		wantReject(t, out, "no_chain")
		if !out.ChainRequired {
			t.Error("bare-token reject did not carry the chain-required signal")
		}
	})
	t.Run("chain-negotiation", func(t *testing.T) {
		out := call("user.creds", sink, "--chain", "negotiate")
		wantAccept(t, out, "acme", strp("alice"))
		if out.ChainRequired {
			t.Error("negotiated accept still carried the chain-required signal")
		}
	})
}
