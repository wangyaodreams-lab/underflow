package cli

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/client"
)

const defaultAlg = crypto.DefaultAlgorithm

func registerInput(email string, params crypto.KDFParams, authKey [32]byte, vaultID string, protKey, nameEnc []byte, invite string) client.RegisterInput {
	return client.RegisterInput{
		Email:             email,
		KDF:               params,
		AuthKey:           authKey,
		VaultID:           vaultID,
		Alg:               defaultAlg,
		VaultNameEnc:      nameEnc,
		ProtectedVaultKey: protKey,
		InviteCode:        invite,
	}
}

func newRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create a new account and vault",
		RunE:  runRegister,
	}
	cmd.Flags().String("profile", "interactive", "argon2 profile: interactive|moderate|paranoid")
	cmd.Flags().String("invite", "", "invite code (when the server requires one)")
	return cmd
}

func runRegister(cmd *cobra.Command, _ []string) error {
	a, err := newApp(cmd)
	if err != nil {
		return err
	}
	if err := a.requireServer(); err != nil {
		return err
	}
	email := a.Cfg.Email
	if email == "" {
		email, err = promptLine("Email: ")
		if err != nil {
			return err
		}
	}
	profile := crypto.Profile(getFlag(cmd, "profile"))
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	var saltArr [16]byte
	copy(saltArr[:], salt)
	params, err := crypto.ParamsForProfile(profile, saltArr)
	if err != nil {
		return err
	}
	password, err := promptNewPassword()
	if err != nil {
		return err
	}
	mk, authKey, kek, err := deriveKeys(password, params)
	if err != nil {
		return err
	}
	defer crypto.ZeroKey(&mk)

	vaultID := newUUID()
	vaultKey, err := crypto.RandomKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroKey(&vaultKey)

	protKey, err := crypto.WrapVaultKey(kek, defaultAlg, params, vaultID, vaultKey)
	if err != nil {
		return err
	}
	nameEnc, err := crypto.SealVaultName(defaultAlg, vaultKey, vaultID, "Default")
	if err != nil {
		return err
	}

	ctx := context.Background()
	sess, err := a.Client.Register(ctx, registerInput(email, params, authKey, vaultID, protKey, nameEnc, getFlag(cmd, "invite")))
	if err != nil {
		return err
	}

	a.Cfg.Email = email
	a.Sec.KDF = toSecret(sess.KDF)
	a.Sec.Alg = defaultAlg
	a.Sec.Vaults = []vaultSecret{{
		ID: vaultID, Alg: defaultAlg,
		Key: base64.StdEncoding.EncodeToString(vaultKey[:]),
	}}
	if err := a.save(); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Registered %s on %s (vault %s)\n", email, a.Cfg.Server, vaultID)
	return nil
}

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in and cache the vault key",
		RunE:  runLogin,
	}
}

func runLogin(cmd *cobra.Command, _ []string) error {
	a, err := newApp(cmd)
	if err != nil {
		return err
	}
	return a.authenticate(cmd, true)
}

func newUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault (derive and cache keys)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := newApp(cmd)
			if err != nil {
				return err
			}
			return a.authenticate(cmd, false)
		},
	}
}

// authenticate logs in (if needed) and caches unwrapped vault keys.
func (a *App) authenticate(cmd *cobra.Command, alwaysLogin bool) error {
	if err := a.requireServer(); err != nil {
		return err
	}
	ctx := context.Background()
	email := a.Cfg.Email
	if email == "" {
		var err error
		email, err = promptLine("Email: ")
		if err != nil {
			return err
		}
	}
	kdfWire, err := a.Client.KDF(ctx, email)
	if err != nil {
		return err
	}
	params, err := kdfWire.ToCrypto()
	if err != nil {
		return err
	}
	password, err := promptSecret("Master password: ")
	if err != nil {
		return err
	}
	mk, authKey, kek, err := deriveKeys(password, params)
	if err != nil {
		return err
	}
	defer crypto.ZeroKey(&mk)

	tokenValid := !alwaysLogin && a.Client.Token != ""
	if tokenValid {
		if _, err := a.Client.Me(ctx); err != nil {
			tokenValid = false
		}
	}
	if !tokenValid {
		sess, err := a.Client.Login(ctx, email, authKey)
		if err != nil {
			return err
		}
		a.Client.Token = sess.Token
	}
	if err := a.unwrapVaults(ctx, kek); err != nil {
		return err
	}
	a.Cfg.Email = email
	a.Sec.KDF = toSecret(kdfWire)
	a.Sec.Alg = defaultAlg
	if err := a.save(); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Unlocked %d vault(s) for %s\n", len(a.Sec.Vaults), email)
	return nil
}

func newLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Forget cached vault keys",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := newApp(cmd)
			if err != nil {
				return err
			}
			a.Sec.Vaults = nil
			a.Sec.KDF = nil
			if err := a.saveSecretsOnly(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Vault locked")
			return nil
		},
	}
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the session and forget cached keys",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := newApp(cmd)
			if err != nil {
				return err
			}
			if a.Client.Token != "" {
				_ = a.Client.Logout(context.Background())
			}
			a.Client.Token = ""
			a.Sec.Token = ""
			a.Sec.Vaults = nil
			a.Sec.KDF = nil
			if err := a.saveSecretsOnly(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out")
			return nil
		},
	}
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the current account and lock state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := newApp(cmd)
			if err != nil {
				return err
			}
			state := "locked"
			if len(a.Sec.Vaults) > 0 {
				state = "unlocked"
			}
			loggedIn := a.Client.Token != ""
			var id string
			if loggedIn {
				if me, err := a.Client.Me(context.Background()); err == nil {
					id = me.UserID
					if a.Cfg.Email == "" {
						a.Cfg.Email = me.Email
					}
				} else {
					loggedIn = false
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "server:   %s\nemail:    %s\nuser id:  %s\nlogged in: %v\nvault:    %s\n",
				a.Cfg.Server, a.Cfg.Email, id, loggedIn, state)
			return nil
		},
	}
}
