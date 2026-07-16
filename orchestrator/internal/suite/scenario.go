package suite

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// Scenario is one language-neutral test case (scenarios.yaml).
type Scenario struct {
	ID       string   `yaml:"id"`
	Mode     string   `yaml:"mode"`
	Creds    string   `yaml:"creds"`
	Nonce    string   `yaml:"nonce"`
	Audience string   `yaml:"audience"`
	Payload  string   `yaml:"payload"` // repo-root-relative, slash-separated
	Repeat   int      `yaml:"repeat"`
	Requires []string `yaml:"requires"`

	// Transport pins the scenario to one transport; empty runs it on all.
	Transport string `yaml:"transport"`

	// Exactly one of Expect / ExpectLast is set. With repeat > 1 the
	// expectation is ExpectLast and applies to the final attempt only;
	// every earlier attempt must be accepted.
	Expect     *Expect `yaml:"expect"`
	ExpectLast *Expect `yaml:"expect_last"`
}

// Expect is the judged outcome. Tenant and User are pointers so that an
// absent field asserts nothing while an explicit value must match.
type Expect struct {
	Accept bool    `yaml:"accept"`
	Tenant *string `yaml:"tenant"`
	User   *string `yaml:"user"`
	Reason string  `yaml:"reason"`
}

// Want returns the expectation for the scenario's final attempt.
func (s *Scenario) Want() *Expect {
	if s.ExpectLast != nil {
		return s.ExpectLast
	}
	return s.Expect
}

// Attempts returns how many times the client runs (same args every time).
func (s *Scenario) Attempts() int {
	if s.Repeat > 1 {
		return s.Repeat
	}
	return 1
}

type scenarioFile struct {
	Scenarios []*Scenario `yaml:"scenarios"`
}

// LoadScenarios parses and validates the scenario suite.
func LoadScenarios(path string) ([]*Scenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open scenarios: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var file scenarioFile
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(file.Scenarios) == 0 {
		return nil, fmt.Errorf("%s: no scenarios", path)
	}
	seen := make(map[string]bool, len(file.Scenarios))
	for _, s := range file.Scenarios {
		if err := s.validate(); err != nil {
			return nil, fmt.Errorf("%s: scenario %q: %w", path, s.ID, err)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("%s: duplicate scenario id %q", path, s.ID)
		}
		seen[s.ID] = true
	}
	return file.Scenarios, nil
}

func (s *Scenario) validate() error {
	switch {
	case s.ID == "":
		return fmt.Errorf("missing id")
	case !slices.Contains(Modes, s.Mode):
		return fmt.Errorf("unknown mode %q", s.Mode)
	case s.Creds == "":
		return fmt.Errorf("missing creds")
	case s.Transport != "" && !slices.Contains(Transports, s.Transport):
		return fmt.Errorf("unknown transport %q", s.Transport)
	case s.Expect != nil && s.ExpectLast != nil:
		return fmt.Errorf("expect and expect_last are mutually exclusive")
	case s.Expect == nil && s.ExpectLast == nil:
		return fmt.Errorf("one of expect or expect_last is required")
	case s.Repeat > 1 && s.ExpectLast == nil:
		return fmt.Errorf("repeat > 1 requires expect_last")
	case s.Repeat <= 1 && s.ExpectLast != nil:
		return fmt.Errorf("expect_last requires repeat > 1")
	}
	if want := s.Want(); !want.Accept && want.Reason == "" {
		return fmt.Errorf("reject expectation missing reason")
	}
	return nil
}
