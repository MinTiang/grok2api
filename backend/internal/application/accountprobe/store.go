package accountprobe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// configStore persists the panel-editable configuration.
//
// The probe config is intentionally not part of the runtime settings document:
// that document is a single revision-checked struct shared with far more
// sensitive fields, and merging a second writer into it would make every panel
// save race the settings page. A small dedicated file keeps the two independent
// while still surviving a restart.
type configStore struct {
	mu   sync.Mutex
	path string
}

func newConfigStore(path string) *configStore {
	return &configStore{path: path}
}

// Load returns the persisted configuration, reporting whether a file was found.
func (s *configStore) Load() (PersistedConfig, bool, error) {
	if s == nil || s.path == "" {
		return PersistedConfig{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return PersistedConfig{}, false, nil
		}
		return PersistedConfig{}, false, err
	}
	var value PersistedConfig
	if err := json.Unmarshal(raw, &value); err != nil {
		return PersistedConfig{}, false, err
	}
	return value, true, nil
}

// Save writes the configuration atomically so a crash cannot leave a truncated
// file that would reset the operator's settings on the next start.
func (s *configStore) Save(value PersistedConfig) error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temp := s.path + ".tmp"
	if err := os.WriteFile(temp, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, s.path)
}
