package suite

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeScenarios(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenarios.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func TestLoadScenarios(t *testing.T) {
	path := writeScenarios(t, `
scenarios:
  - id: signed/valid
    mode: signed
    creds: user.creds
    expect: { accept: true, tenant: acme, user: alice }
  - id: signed/replay
    mode: signed
    creds: user.creds
    nonce: n-1
    repeat: 2
    requires: [replay]
    expect_last: { accept: false, reason: replay }
  - id: message/valid
    mode: message
    creds: user.creds
    audience: interop://sink
    payload: fixture/payloads/hello.bin
    expect: { accept: true }
`)
	scs, err := LoadScenarios(path)
	require.NoError(t, err)
	require.Len(t, scs, 3)

	require.Equal(t, "signed/valid", scs[0].ID)
	require.Equal(t, 1, scs[0].Attempts())
	require.True(t, scs[0].Want().Accept)
	require.Equal(t, "acme", *scs[0].Want().Tenant)
	require.Equal(t, "alice", *scs[0].Want().User)

	require.Equal(t, 2, scs[1].Attempts())
	require.False(t, scs[1].Want().Accept)
	require.Equal(t, "replay", scs[1].Want().Reason)
	require.Nil(t, scs[1].Want().Tenant)

	require.Equal(t, "interop://sink", scs[2].Audience)
	require.Equal(t, "fixture/payloads/hello.bin", scs[2].Payload)
}

func TestLoadScenariosErrors(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "duplicate ids",
			body: `
scenarios:
  - { id: a, mode: signed, creds: c, expect: { accept: true } }
  - { id: a, mode: signed, creds: c, expect: { accept: true } }
`,
			wantErr: "duplicate scenario id",
		},
		{
			name:    "expect and expect_last are exclusive",
			body:    "scenarios:\n  - { id: a, mode: signed, creds: c, repeat: 2, expect: { accept: true }, expect_last: { accept: true } }\n",
			wantErr: "mutually exclusive",
		},
		{
			name:    "repeat requires expect_last",
			body:    "scenarios:\n  - { id: a, mode: signed, creds: c, repeat: 2, expect: { accept: true } }\n",
			wantErr: "repeat > 1 requires expect_last",
		},
		{
			name:    "expect_last requires repeat",
			body:    "scenarios:\n  - { id: a, mode: signed, creds: c, expect_last: { accept: false, reason: r } }\n",
			wantErr: "expect_last requires repeat > 1",
		},
		{
			name:    "reject needs a reason",
			body:    "scenarios:\n  - { id: a, mode: signed, creds: c, expect: { accept: false } }\n",
			wantErr: "reject expectation missing reason",
		},
		{
			name:    "unknown mode",
			body:    "scenarios:\n  - { id: a, mode: bearer, creds: c, expect: { accept: true } }\n",
			wantErr: `unknown mode "bearer"`,
		},
		{
			name:    "unknown field",
			body:    "scenarios:\n  - { id: a, mode: signed, creds: c, expects: { accept: true } }\n",
			wantErr: "field expects not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadScenarios(writeScenarios(t, tt.body))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
