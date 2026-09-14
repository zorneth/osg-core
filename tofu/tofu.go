// Package tofu stores trust-on-first-use SHA256 fingerprints for binaries.
package tofu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Store maps absolute binary path → sha256 hex.
type Store struct {
	mu   sync.Mutex
	path string
	data map[string]string
}

// Open loads or creates a TOFU store at path (JSON).
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]string{}}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, fmt.Errorf("tofu: parse: %w", err)
		}
		if s.data == nil {
			s.data = map[string]string{}
		}
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return s, s.flushLocked()
}

// DefaultPath returns $XDG_STATE_HOME/osg/binary-tofu.json (or ~/.local/state/…).
func DefaultPath() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "osg", "binary-tofu.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "osg-binary-tofu.json")
	}
	return filepath.Join(home, ".local", "state", "osg", "binary-tofu.json")
}

// VerifyOrCache hashes path and either records first-seen or denies on mismatch.
func (s *Store) VerifyOrCache(binPath string) (hash string, err error) {
	if s == nil {
		return "", fmt.Errorf("tofu: nil store")
	}
	abs, err := filepath.Abs(binPath)
	if err != nil {
		return "", err
	}
	sum, err := hashFile(abs)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.data[abs]; ok {
		if prev != sum {
			return sum, fmt.Errorf("tofu: binary fingerprint changed for %s", abs)
		}
		return sum, nil
	}
	s.data[abs] = sum
	return sum, s.flushLocked()
}

func (s *Store) flushLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
