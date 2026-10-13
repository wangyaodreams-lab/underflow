package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/client"
)

// App carries per-invocation CLI state.
type App struct {
	ConfigPath  string
	SecretsPath string
	Cfg         cliConfig
	Sec         secrets
	Client      *client.Client
}

func newApp(cmd *cobra.Command) (*App, error) {
	dir := getFlag(cmd, "config-dir")
	if dir == "" {
		var err error
		dir, err = defaultConfigDir()
		if err != nil {
			return nil, err
		}
	}
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, "config.toml")
	secPath := filepath.Join(dir, "secrets.json")

	c, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if v := getFlag(cmd, "server"); v != "" {
		c.Server = v
	}
	if v := getFlag(cmd, "email"); v != "" {
		c.Email = v
	}
	if c.DeviceID == "" {
		c.DeviceID = randomID()
	}
	s, err := loadSecrets(secPath)
	if err != nil {
		return nil, err
	}
	cl := client.New(c.Server)
	cl.Token = s.Token
	return &App{ConfigPath: cfgPath, SecretsPath: secPath, Cfg: c, Sec: s, Client: cl}, nil
}

func (a *App) save() error {
	if err := saveConfig(a.ConfigPath, a.Cfg); err != nil {
		return err
	}
	a.Sec.Token = a.Client.Token
	return saveSecrets(a.SecretsPath, a.Sec)
}

func (a *App) saveSecretsOnly() error {
	a.Sec.Token = a.Client.Token
	return saveSecrets(a.SecretsPath, a.Sec)
}

func (a *App) requireServer() error {
	if a.Cfg.Server == "" {
		return errors.New("no server configured; pass --server or run `underflow register --server <url>`")
	}
	return nil
}

// requireUnlocked ensures the session token and vault keys are cached.
func (a *App) requireUnlocked() error {
	if a.Client.Token == "" {
		return errors.New("not logged in; run `underflow login`")
	}
	if len(a.Sec.Vaults) == 0 {
		return errors.New("vault is locked; run `underflow unlock`")
	}
	return nil
}

// deriveKeys derives all key material from a master password and KDF params.
func deriveKeys(password string, kdf crypto.KDFParams) (mk, authKey, kek [32]byte, err error) {
	mk, err = crypto.DeriveMasterKeyFromString(password, kdf)
	if err != nil {
		return
	}
	authKey, err = crypto.DeriveAuthKey(mk, kdf.Salt[:])
	if err != nil {
		return
	}
	kek, err = crypto.DeriveKEK(mk, kdf.Salt[:])
	return
}

// unwrapVaults fetches vaults and caches their unwrapped keys.
func (a *App) unwrapVaults(ctx context.Context, kek [32]byte) error {
	vaults, err := a.Client.ListVaults(ctx)
	if err != nil {
		return err
	}
	var out []vaultSecret
	for _, v := range vaults {
		env, err := base64.StdEncoding.DecodeString(v.ProtectedVaultKey)
		if err != nil {
			return fmt.Errorf("vault %s: bad protected key: %w", v.ID, err)
		}
		vk, err := crypto.UnwrapVaultKey(kek, v.ID, env)
		if err != nil {
			return fmt.Errorf("vault %s: could not unwrap key (wrong master password?): %w", v.ID, err)
		}
		out = append(out, vaultSecret{ID: v.ID, Alg: v.Alg, Key: base64.StdEncoding.EncodeToString(vk[:])})
	}
	a.Sec.Vaults = out
	return nil
}

// vaultKeyFor returns the cached vault key by id, or the only vault's key.
func (a *App) vaultKeyFor(id string) ([32]byte, string, uint8, error) {
	var zero [32]byte
	if len(a.Sec.Vaults) == 0 {
		return zero, "", 0, errors.New("vault is locked; run `underflow unlock`")
	}
	if id == "" {
		if len(a.Sec.Vaults) > 1 {
			return zero, "", 0, errors.New("multiple vaults present; pass --vault <id>")
		}
		id = a.Sec.Vaults[0].ID
	}
	for _, v := range a.Sec.Vaults {
		if v.ID == id {
			raw, err := base64.StdEncoding.DecodeString(v.Key)
			if err != nil || len(raw) != 32 {
				return zero, "", 0, fmt.Errorf("cached key for vault %s is corrupt", id)
			}
			var k [32]byte
			copy(k[:], raw)
			return k, v.ID, v.Alg, nil
		}
	}
	return zero, "", 0, fmt.Errorf("vault %s is not unlocked", id)
}

// sync decrypted returns all live (non-deleted) items decrypted with the
// cached vault keys.
type decryptedItem struct {
	VaultID string
	Item    client.Item
	Plain   []byte
}

func (a *App) syncDecrypted(ctx context.Context) ([]decryptedItem, int64, error) {
	res, err := a.Client.Sync(ctx, 0)
	if err != nil {
		return nil, 0, err
	}
	var out []decryptedItem
	for _, it := range res.Items {
		if it.Deleted {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(it.Blob)
		if err != nil {
			return nil, 0, fmt.Errorf("item %s: bad blob: %w", it.ID, err)
		}
		vk, _, _, err := a.vaultKeyFor(it.VaultID)
		if err != nil {
			return nil, 0, err
		}
		plain, err := crypto.OpenItemWithVaultKey(vk, it.VaultID, it.ID, blob)
		if err != nil {
			return nil, 0, fmt.Errorf("item %s: decrypt failed: %w", it.ID, err)
		}
		out = append(out, decryptedItem{VaultID: it.VaultID, Item: it, Plain: plain})
	}
	return out, res.Revision, nil
}

func (a *App) now() time.Time { return time.Now().UTC() }
