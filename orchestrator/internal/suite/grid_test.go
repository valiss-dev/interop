package suite

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func testEntry(id string, spec []int, server *ServerRole, client *ClientRole) *Entry {
	return &Entry{
		Manifest: Manifest{
			ID:      id,
			Library: "valiss-" + id,
			Version: "0.1",
			Spec:    spec,
			Server:  server,
			Client:  client,
			Build:   Build{Dockerfile: "Dockerfile"},
		},
		Dir: "/harness/" + id,
	}
}

func fullServer() *ServerRole {
	return &ServerRole{
		Transports: []string{"http", "grpc"},
		Modes:      []string{"signed", "message"},
		Features:   map[string]bool{"allowlist": true, "replay": true, "bearer": true},
	}
}

func fullClient() *ClientRole {
	return &ClientRole{Transports: []string{"http", "grpc"}, Modes: []string{"signed", "message"}}
}

func accept() *Expect { return &Expect{Accept: true} }

func cellOf(t *testing.T, cells []*Cell, transport, server, client string) *Cell {
	t.Helper()
	for _, c := range cells {
		if c.Transport == transport && c.Server.ID == server && c.Client.ID == client {
			return c
		}
	}
	t.Fatalf("no cell (%s %s -> %s)", transport, server, client)
	return nil
}

func scenarioIDs(scs []*Scenario) []string {
	ids := make([]string, len(scs))
	for i, sc := range scs {
		ids[i] = sc.ID
	}
	return ids
}

func TestComputeGridPairing(t *testing.T) {
	tests := []struct {
		name    string
		entries []*Entry
		want    []string // "transport server client"
	}{
		{
			name:    "single dual-role entry pairs with itself on both transports",
			entries: []*Entry{testEntry("a", []int{1}, fullServer(), fullClient())},
			want:    []string{"http a a", "grpc a a"},
		},
		{
			name: "two dual-role entries give the full cross product",
			entries: []*Entry{
				testEntry("a", []int{1}, fullServer(), fullClient()),
				testEntry("b", []int{1}, fullServer(), fullClient()),
			},
			want: []string{
				"http a a", "http a b", "http b a", "http b b",
				"grpc a a", "grpc a b", "grpc b a", "grpc b b",
			},
		},
		{
			name: "server-only http entry pairs only as server on http",
			entries: []*Entry{
				testEntry("a", []int{1}, fullServer(), fullClient()),
				testEntry("srv", []int{1}, &ServerRole{Transports: []string{"http"}, Modes: []string{"signed"}}, nil),
			},
			want: []string{"http a a", "http srv a", "grpc a a"},
		},
		{
			name: "client transports gate the pairing per transport",
			entries: []*Entry{
				testEntry("a", []int{1}, fullServer(), fullClient()),
				testEntry("h", []int{1}, nil, &ClientRole{Transports: []string{"http"}, Modes: []string{"signed"}}),
			},
			want: []string{"http a a", "http a h", "grpc a a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cells := ComputeGrid(tt.entries, nil)
			var got []string
			for _, c := range cells {
				got = append(got, fmt.Sprintf("%s %s %s", c.Transport, c.Server.ID, c.Client.ID))
			}
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestComputeGridSpecIntersection(t *testing.T) {
	tests := []struct {
		name             string
		serverSpec       []int
		clientSpec       []int
		wantIncompatible bool
	}{
		{"shared spec", []int{1}, []int{1}, false},
		{"overlapping specs", []int{1, 2}, []int{2}, false},
		{"disjoint specs", []int{1}, []int{2}, true},
		{"pre-spec legacy vs spec-1", []int{}, []int{1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := []*Entry{
				testEntry("s", tt.serverSpec, fullServer(), nil),
				testEntry("c", tt.clientSpec, nil, fullClient()),
			}
			scenarios := []*Scenario{{ID: "x", Mode: "signed", Creds: "a.creds", Expect: accept()}}
			cell := cellOf(t, ComputeGrid(entries, scenarios), "http", "s", "c")
			require.Equal(t, tt.wantIncompatible, cell.Incompatible)
			if tt.wantIncompatible {
				require.Empty(t, cell.Applicable)
				require.Empty(t, cell.Skipped)
			} else {
				require.Len(t, cell.Applicable, 1)
			}
		})
	}
}

func TestComputeGridScenarioGating(t *testing.T) {
	scenarios := []*Scenario{
		{ID: "signed/basic", Mode: "signed", Creds: "a.creds", Expect: accept()},
		{ID: "signed/bearer", Mode: "signed", Creds: "b.creds", Requires: []string{"bearer"}, Expect: accept()},
		{ID: "signed/replay", Mode: "signed", Creds: "a.creds", Repeat: 2, Requires: []string{"replay"},
			ExpectLast: &Expect{Accept: false, Reason: "replay"}},
		{ID: "signed/http-only", Mode: "signed", Creds: "a.creds", Transport: "http", Expect: accept()},
		{ID: "message/basic", Mode: "message", Creds: "a.creds", Expect: accept()},
	}
	tests := []struct {
		name        string
		server      *ServerRole
		client      *ClientRole
		transport   string
		wantRun     []string
		wantSkipped []string
	}{
		{
			name:      "full capabilities run everything on http",
			server:    fullServer(),
			client:    fullClient(),
			transport: "http",
			wantRun:   []string{"signed/basic", "signed/bearer", "signed/replay", "signed/http-only", "message/basic"},
		},
		{
			name:      "transport pin drops the scenario elsewhere silently",
			server:    fullServer(),
			client:    fullClient(),
			transport: "grpc",
			wantRun:   []string{"signed/basic", "signed/bearer", "signed/replay", "message/basic"},
		},
		{
			name: "missing server features skip, not fail",
			server: &ServerRole{Transports: []string{"http"}, Modes: []string{"signed", "message"},
				Features: map[string]bool{"bearer": false}},
			client:      fullClient(),
			transport:   "http",
			wantRun:     []string{"signed/basic", "signed/http-only", "message/basic"},
			wantSkipped: []string{"signed/bearer", "signed/replay"},
		},
		{
			name:      "mode outside the server's modes is not applicable",
			server:    &ServerRole{Transports: []string{"http"}, Modes: []string{"signed"}, Features: map[string]bool{"bearer": true, "replay": true}},
			client:    fullClient(),
			transport: "http",
			wantRun:   []string{"signed/basic", "signed/bearer", "signed/replay", "signed/http-only"},
		},
		{
			name:      "mode outside the client's modes is not applicable",
			server:    fullServer(),
			client:    &ClientRole{Transports: []string{"http"}, Modes: []string{"message"}},
			transport: "http",
			wantRun:   []string{"message/basic"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := []*Entry{
				testEntry("s", []int{1}, tt.server, nil),
				testEntry("c", []int{1}, nil, tt.client),
			}
			cell := cellOf(t, ComputeGrid(entries, scenarios), tt.transport, "s", "c")
			require.Equal(t, tt.wantRun, scenarioIDs(cell.Applicable))
			var skipped []string
			for _, sk := range cell.Skipped {
				skipped = append(skipped, sk.Scenario.ID)
				require.NotEmpty(t, sk.Reason)
			}
			require.Equal(t, tt.wantSkipped, skipped)
		})
	}
}
