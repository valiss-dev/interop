// Package smoke proves the go-0.12 harness end-to-end: it builds both
// runnables, starts the server against the committed fixture, and drives the
// client through the scenarios.yaml suite on each transport and mode,
// asserting the contract outcomes (CONTRACT.md) including the §7 reason
// codes on rejection.
package smoke

import (
	"bufio"
	"encoding/json"
	"fmt"
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
	Status   any              `json:"status"`
	Reason   *string          `json:"reason"`
	Identity *outcomeIdentity `json:"identity"`
}

type outcomeIdentity struct {
	Tenant string  `json:"tenant"`
	User   *string `json:"user"`
}

// bins builds the server and client once per test binary.
func bins(t *testing.T) (server, client string) {
	t.Helper()
	dir := t.TempDir()
	server = filepath.Join(dir, "server")
	client = filepath.Join(dir, "client")
	for target, pkg := range map[string]string{server: "./cmd/server", client: "./cmd/client"} {
		out, err := exec.Command("go", "build", "-o", target, pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("build %s: %v\n%s", pkg, err, out)
		}
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
func startServer(t *testing.T, bin, transport, mode string) (addr string) {
	t.Helper()
	fixture := fixtureDir(t)
	cmd := exec.Command(bin,
		"--transport", transport,
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

// runClient invokes the harness client once and parses its outcome line. The
// client must exit 0 whether the request was accepted or rejected.
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

// wantAccept asserts the accept outcome for a transport: HTTP 200 or gRPC
// OK, no reason, and the expected identity.
func wantAccept(t *testing.T, transport string, out outcome, tenant string, user *string) {
	t.Helper()
	wantStatus(t, transport, out, 200, "OK")
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

// wantReject asserts the reject outcome: HTTP 401 or gRPC UNAUTHENTICATED,
// the expected §7 reason, and no identity.
func wantReject(t *testing.T, transport string, out outcome, reason string) {
	t.Helper()
	wantStatus(t, transport, out, 401, "UNAUTHENTICATED")
	if out.Reason == nil || *out.Reason != reason {
		t.Errorf("reason = %v, want %q", out.Reason, reason)
	}
	if out.Identity != nil {
		t.Errorf("reject carried identity %+v", out.Identity)
	}
}

func wantStatus(t *testing.T, transport string, out outcome, httpWant int, grpcWant string) {
	t.Helper()
	switch transport {
	case "http":
		got, ok := out.Status.(float64)
		if !ok || int(got) != httpWant {
			t.Errorf("status = %v, want %d", out.Status, httpWant)
		}
	case "grpc":
		got, ok := out.Status.(string)
		if !ok || got != grpcWant {
			t.Errorf("status = %v, want %q", out.Status, grpcWant)
		}
	}
}

func strp(s string) *string { return &s }

func TestSigned(t *testing.T) {
	server, client := bins(t)
	fixture := fixtureDir(t)
	credsPath := func(name string) string { return filepath.Join(fixture, "creds", name) }

	for _, transport := range []string{"http", "grpc"} {
		t.Run(transport, func(t *testing.T) {
			addr := startServer(t, server, transport, "signed")
			call := func(creds string, extra ...string) outcome {
				args := append([]string{
					"--transport", transport, "--addr", addr,
					"--creds", credsPath(creds),
				}, extra...)
				return runClient(t, client, args...)
			}

			t.Run("account-valid", func(t *testing.T) {
				wantAccept(t, transport, call("account.creds"), "acme", nil)
			})
			t.Run("user-valid", func(t *testing.T) {
				wantAccept(t, transport, call("user.creds"), "acme", strp("alice"))
			})
			t.Run("bearer-valid", func(t *testing.T) {
				wantAccept(t, transport, call("bearer.creds"), "acme", strp("alice"))
			})
			t.Run("account-revoked", func(t *testing.T) {
				wantReject(t, transport, call("revoked.creds"), "not_allowlisted")
			})
			t.Run("expired", func(t *testing.T) {
				wantReject(t, transport, call("expired.creds"), "expired")
			})
			t.Run("wrong-key", func(t *testing.T) {
				wantReject(t, transport, call("wrongkey.creds"), "bad_request_signature")
			})
			t.Run("replay", func(t *testing.T) {
				nonce := fmt.Sprintf("interop-nonce-%s", transport)
				wantAccept(t, transport, call("user.creds", "--nonce", nonce), "acme", strp("alice"))
				wantReject(t, transport, call("user.creds", "--nonce", nonce), "replay")
			})
		})
	}
}

func TestMessage(t *testing.T) {
	server, client := bins(t)
	fixture := fixtureDir(t)

	for _, transport := range []string{"http", "grpc"} {
		t.Run(transport, func(t *testing.T) {
			addr := startServer(t, server, transport, "message")
			call := func(audience string) outcome {
				return runClient(t, client,
					"--transport", transport, "--addr", addr,
					"--creds", filepath.Join(fixture, "creds", "user.creds"),
					"--mode", "message",
					"--audience", audience,
					"--payload", filepath.Join(fixture, "payloads", "hello.bin"),
				)
			}

			t.Run("valid", func(t *testing.T) {
				wantAccept(t, transport, call("interop://sink"), "acme", strp("alice"))
			})
			t.Run("wrong-audience", func(t *testing.T) {
				wantReject(t, transport, call("interop://other"), "wrong_audience")
			})
		})
	}
}
