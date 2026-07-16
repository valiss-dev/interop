// Package suite loads the static matrix inputs — harness entry manifests
// and the scenario file — and derives the grid of cells per the pairing and
// gating rules in CONTRACT.md and harness/README.md.
package suite

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"
)

const (
	TransportHTTP = "http"
	TransportGRPC = "grpc"

	ModeSigned  = "signed"
	ModeMessage = "message"
)

// Transports is the fixed contract transport set, in matrix order.
var Transports = []string{TransportHTTP, TransportGRPC}

// Modes is the fixed contract mode set, in execution order: scenarios are
// grouped by mode so a cell's server starts once per (cell, mode).
var Modes = []string{ModeSigned, ModeMessage}

// Manifest is an entry's capability declaration (harness/README.md schema).
type Manifest struct {
	ID             string      `yaml:"id"`
	Library        string      `yaml:"library"`
	Adapter        string      `yaml:"adapter"`
	AdapterVersion string      `yaml:"adapter_version"`
	Version        string      `yaml:"version"`
	Spec           []int       `yaml:"spec"`
	Server         *ServerRole `yaml:"server"`
	Client         *ClientRole `yaml:"client"`
	Issue          []string    `yaml:"issue"`
	Build          Build       `yaml:"build"`
}

// ServerRole declares what the entry's server runnable provides.
type ServerRole struct {
	Transports []string        `yaml:"transports"`
	Modes      []string        `yaml:"modes"`
	Features   map[string]bool `yaml:"features"`
}

// ClientRole declares what the entry's client runnable can call.
type ClientRole struct {
	Transports []string `yaml:"transports"`
	Modes      []string `yaml:"modes"`
}

// Build names the entry's image recipe.
type Build struct {
	Dockerfile string `yaml:"dockerfile"`
}

// Entry is a discovered harness entry: its manifest plus its directory.
type Entry struct {
	Manifest
	Dir string
}

// DiscoverEntries parses and validates every harness/*/manifest.yaml,
// returning entries in directory order.
func DiscoverEntries(harnessDir string) ([]*Entry, error) {
	dirents, err := os.ReadDir(harnessDir)
	if err != nil {
		return nil, fmt.Errorf("read harness dir: %w", err)
	}
	var entries []*Entry
	for _, d := range dirents {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(harnessDir, d.Name())
		path := filepath.Join(dir, "manifest.yaml")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		m, err := loadManifest(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if m.ID != d.Name() {
			return nil, fmt.Errorf("%s: id %q does not match directory name %q", path, m.ID, d.Name())
		}
		entries = append(entries, &Entry{Manifest: *m, Dir: dir})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries with a manifest.yaml under %s", harnessDir)
	}
	return entries, nil
}

func loadManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	switch {
	case m.ID == "":
		return fmt.Errorf("manifest missing id")
	case m.Library == "":
		return fmt.Errorf("manifest missing library")
	case m.Version == "":
		return fmt.Errorf("manifest missing version")
	case m.Build.Dockerfile == "":
		return fmt.Errorf("manifest missing build.dockerfile")
	case m.Server == nil && m.Client == nil:
		return fmt.Errorf("manifest declares no role (server or client)")
	}
	if m.Server != nil {
		if err := validateRole("server", m.Server.Transports, m.Server.Modes); err != nil {
			return err
		}
	}
	if m.Client != nil {
		if err := validateRole("client", m.Client.Transports, m.Client.Modes); err != nil {
			return err
		}
	}
	return nil
}

func validateRole(role string, roleTransports, roleModes []string) error {
	if len(roleTransports) == 0 {
		return fmt.Errorf("%s role declares no transports", role)
	}
	for _, t := range roleTransports {
		if !slices.Contains(Transports, t) {
			return fmt.Errorf("%s role: unknown transport %q", role, t)
		}
	}
	if len(roleModes) == 0 {
		return fmt.Errorf("%s role declares no modes", role)
	}
	for _, m := range roleModes {
		if !slices.Contains(Modes, m) {
			return fmt.Errorf("%s role: unknown mode %q", role, m)
		}
	}
	return nil
}
