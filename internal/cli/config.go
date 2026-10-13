package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wangyaodreams-lab/underflow/internal/client"
)

// config holds non-secret CLI settings, persisted as a small TOML subset.
type cliConfig struct {
	Server   string
	Email    string
	DeviceID string
}

// secrets holds sensitive session material in a 0600 JSON file.
type secrets struct {
	Token  string        `json:"token,omitempty"`
	KDF    *kdfSecret    `json:"kdf,omitempty"`
	Alg    uint8         `json:"alg,omitempty"`
	Vaults []vaultSecret `json:"vaults,omitempty"`
	Last   int64         `json:"lastRevision,omitempty"`
}

type kdfSecret struct {
	ID   uint8  `json:"id"`
	M    uint32 `json:"m"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
	Salt string `json:"salt"`
}

type vaultSecret struct {
	ID  string `json:"id"`
	Alg uint8  `json:"alg"`
	Key string `json:"key"` // base64 of the 32-byte vault key
}

func defaultConfigDir() (string, error) {
	if dir := os.Getenv("UNDERFLOW_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "underflow"), nil
}

func loadConfig(path string) (cliConfig, error) {
	var c cliConfig
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator's config directory.
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch key {
		case "server":
			c.Server = val
		case "email":
			c.Email = val
		case "device_id":
			c.DeviceID = val
		}
	}
	return c, nil
}

func saveConfig(path string, c cliConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Underflow CLI configuration\n")
	if c.Server != "" {
		fmt.Fprintf(&b, "server = %q\n", c.Server)
	}
	if c.Email != "" {
		fmt.Fprintf(&b, "email = %q\n", c.Email)
	}
	if c.DeviceID != "" {
		fmt.Fprintf(&b, "device_id = %q\n", c.DeviceID)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func loadSecrets(path string) (secrets, error) {
	var s secrets
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator's config directory.
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	return s, nil
}

func saveSecrets(path string, s secrets) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// kdfFromSecret converts a stored KDF descriptor.
func toSecret(k client.KDFParams) *kdfSecret {
	return &kdfSecret{ID: k.ID, M: k.M, T: k.T, P: k.P, Salt: k.Salt}
}
