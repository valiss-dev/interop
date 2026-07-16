package matrix

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/valiss-dev/interop/orchestrator/internal/runner"
	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

func strp(s string) *string { return &s }

func TestJudgeFinal(t *testing.T) {
	acceptHTTP := runner.Outcome{Status: float64(200), Identity: &runner.Identity{Tenant: "acme", User: strp("alice")}}
	rejectHTTP := runner.Outcome{Status: float64(401), Reason: strp("replay")}

	tests := []struct {
		name      string
		transport string
		want      *suite.Expect
		out       runner.Outcome
		wantErr   string
	}{
		{
			name:      "http accept with tenant and user",
			transport: "http",
			want:      &suite.Expect{Accept: true, Tenant: strp("acme"), User: strp("alice")},
			out:       acceptHTTP,
		},
		{
			name:      "grpc accept",
			transport: "grpc",
			want:      &suite.Expect{Accept: true, Tenant: strp("acme")},
			out:       runner.Outcome{Status: "OK", Identity: &runner.Identity{Tenant: "acme"}},
		},
		{
			name:      "absent expect fields assert nothing",
			transport: "http",
			want:      &suite.Expect{Accept: true},
			out:       acceptHTTP,
		},
		{
			name:      "expected user must be present",
			transport: "http",
			want:      &suite.Expect{Accept: true, User: strp("alice")},
			out:       runner.Outcome{Status: float64(200), Identity: &runner.Identity{Tenant: "acme"}},
			wantErr:   `user = null, want "alice"`,
		},
		{
			name:      "tenant mismatch",
			transport: "http",
			want:      &suite.Expect{Accept: true, Tenant: strp("other")},
			out:       acceptHTTP,
			wantErr:   `tenant = "acme", want "other"`,
		},
		{
			name:      "accept requires the exact accept status",
			transport: "http",
			want:      &suite.Expect{Accept: true},
			out:       runner.Outcome{Status: float64(204), Identity: &runner.Identity{Tenant: "acme"}},
			wantErr:   "expected accept",
		},
		{
			name:      "accept must not carry a reason",
			transport: "http",
			want:      &suite.Expect{Accept: true},
			out:       runner.Outcome{Status: float64(200), Reason: strp("expired"), Identity: &runner.Identity{Tenant: "acme"}},
			wantErr:   `accept carried reason "expired"`,
		},
		{
			name:      "accept must carry an identity",
			transport: "grpc",
			want:      &suite.Expect{Accept: true},
			out:       runner.Outcome{Status: "OK"},
			wantErr:   "accept carried no identity",
		},
		{
			name:      "http reject with matching reason",
			transport: "http",
			want:      &suite.Expect{Accept: false, Reason: "replay"},
			out:       rejectHTTP,
		},
		{
			name:      "grpc reject with matching reason",
			transport: "grpc",
			want:      &suite.Expect{Accept: false, Reason: "expired"},
			out:       runner.Outcome{Status: "UNAUTHENTICATED", Reason: strp("expired")},
		},
		{
			name:      "reject reason mismatch",
			transport: "http",
			want:      &suite.Expect{Accept: false, Reason: "expired"},
			out:       rejectHTTP,
			wantErr:   `reason = "replay", want "expired"`,
		},
		{
			name:      "reject without reason",
			transport: "http",
			want:      &suite.Expect{Accept: false, Reason: "expired"},
			out:       runner.Outcome{Status: float64(401)},
			wantErr:   "reject carried no reason",
		},
		{
			name:      "reject must not carry identity",
			transport: "http",
			want:      &suite.Expect{Accept: false, Reason: "expired"},
			out:       runner.Outcome{Status: float64(401), Reason: strp("expired"), Identity: &runner.Identity{Tenant: "acme"}},
			wantErr:   "reject carried identity",
		},
		{
			name:      "reject requires the exact reject status",
			transport: "http",
			want:      &suite.Expect{Accept: false, Reason: "expired"},
			out:       runner.Outcome{Status: float64(500), Reason: strp("expired")},
			wantErr:   "expected reject",
		},
		{
			name:      "expected accept got reject",
			transport: "grpc",
			want:      &suite.Expect{Accept: true},
			out:       runner.Outcome{Status: "UNAUTHENTICATED", Reason: strp("expired")},
			wantErr:   "expected accept",
		},
		{
			name:      "http status must be numeric",
			transport: "http",
			want:      &suite.Expect{Accept: true},
			out:       runner.Outcome{Status: "OK", Identity: &runner.Identity{Tenant: "acme"}},
			wantErr:   "expected accept",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := judgeFinal(tt.transport, tt.want, tt.out)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestJudgeWarmup(t *testing.T) {
	require.NoError(t, judgeWarmup("http", runner.Outcome{Status: float64(200)}))
	require.NoError(t, judgeWarmup("grpc", runner.Outcome{Status: "OK"}))
	require.ErrorContains(t,
		judgeWarmup("http", runner.Outcome{Status: float64(401), Reason: strp("replay")}),
		"expected accept")
}
