package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Outcome mirrors the client's one-line report (CONTRACT.md): the raw HTTP
// status int or canonical gRPC code string, the server's §7 reject reason,
// and the accepted identity.
type Outcome struct {
	Status   any       `json:"status"`
	Reason   *string   `json:"reason"`
	Identity *Identity `json:"identity"`

	// ChainRequired reports whether the final response carried the
	// message-mode chain-negotiation signal; absent means false.
	ChainRequired bool `json:"chain_required"`
}

// Identity is the accepted identity as reported by the client.
type Identity struct {
	Tenant string  `json:"tenant"`
	User   *string `json:"user"`
}

// ParseOutcome extracts the contract JSON line from client stdout.
func ParseOutcome(raw []byte) (Outcome, error) {
	for line := range bytes.Lines(raw) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var out Outcome
		if err := json.Unmarshal(line, &out); err != nil {
			return Outcome{}, fmt.Errorf("client output %q is not the contract JSON line: %w", line, err)
		}
		if out.Status == nil {
			return Outcome{}, fmt.Errorf("client output %q carries no status", line)
		}
		return out, nil
	}
	return Outcome{}, errors.New("client produced no output")
}
