package suite

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeManifest(t *testing.T, harnessDir, id, body string) {
	t.Helper()
	dir := filepath.Join(harnessDir, id)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(body), 0o644))
}

const validManifest = `
id: go-0.1
library: valiss-go
version: "0.1"
spec: [1]
server:
  transports: [http, grpc]
  modes: [signed, message]
  features:
    allowlist: true
client:
  transports: [http]
  modes: [signed]
issue: [user]
build:
  dockerfile: Dockerfile
`

func TestDiscoverEntries(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "go-0.1", validManifest)

	entries, err := DiscoverEntries(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	e := entries[0]
	require.Equal(t, "go-0.1", e.ID)
	require.Equal(t, "valiss-go", e.Library)
	require.Equal(t, []int{1}, e.Spec)
	require.Equal(t, filepath.Join(dir, "go-0.1"), e.Dir)
	require.True(t, e.Server.Features["allowlist"])
	require.Equal(t, []string{"http"}, e.Client.Transports)
}

func TestDiscoverEntriesErrors(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		body    string
		wantErr string
	}{
		{
			name:    "id must equal directory name",
			id:      "go-0.2",
			body:    validManifest,
			wantErr: "does not match directory name",
		},
		{
			name:    "unknown fields are rejected",
			id:      "go-0.1",
			body:    validManifest + "bogus: true\n",
			wantErr: "field bogus not found",
		},
		{
			name:    "a role is required",
			id:      "go-0.1",
			body:    "id: go-0.1\nlibrary: l\nversion: \"1\"\nbuild: {dockerfile: Dockerfile}\n",
			wantErr: "declares no role",
		},
		{
			name:    "unknown transport is rejected",
			id:      "go-0.1",
			body:    "id: go-0.1\nlibrary: l\nversion: \"1\"\nbuild: {dockerfile: Dockerfile}\nclient: {transports: [tcp], modes: [signed]}\n",
			wantErr: `unknown transport "tcp"`,
		},
		{
			name:    "dockerfile is required",
			id:      "go-0.1",
			body:    "id: go-0.1\nlibrary: l\nversion: \"1\"\nclient: {transports: [http], modes: [signed]}\n",
			wantErr: "missing build.dockerfile",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeManifest(t, dir, tt.id, tt.body)
			_, err := DiscoverEntries(dir)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
