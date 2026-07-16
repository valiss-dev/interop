package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func strp(s string) *string { return &s }

func TestParseOutcome(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Outcome
		wantErr string
	}{
		{
			name: "http accept",
			raw:  `{"status":200,"reason":null,"identity":{"tenant":"acme","user":"alice"}}` + "\n",
			want: Outcome{Status: float64(200), Identity: &Identity{Tenant: "acme", User: strp("alice")}},
		},
		{
			name: "grpc reject",
			raw:  `{"status":"UNAUTHENTICATED","reason":"replay","identity":null}`,
			want: Outcome{Status: "UNAUTHENTICATED", Reason: strp("replay")},
		},
		{
			name: "leading blank lines are skipped",
			raw:  "\n\n" + `{"status":200,"reason":null,"identity":{"tenant":"acme","user":null}}`,
			want: Outcome{Status: float64(200), Identity: &Identity{Tenant: "acme"}},
		},
		{name: "empty output", raw: "", wantErr: "no output"},
		{name: "not json", raw: "ready 127.0.0.1:1234", wantErr: "not the contract JSON line"},
		{name: "missing status", raw: `{"reason":null}`, wantErr: "no status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseOutcome([]byte(tt.raw))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
