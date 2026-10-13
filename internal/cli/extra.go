package cli

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/client"
	"github.com/wangyaodreams-lab/underflow/internal/pwgen"
	"github.com/wangyaodreams-lab/underflow/internal/vault"
)

func newSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Fetch and decrypt changes from the server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := newApp(cmd)
			if err != nil {
				return err
			}
			if err := a.requireUnlocked(); err != nil {
				return err
			}
			res, err := a.Client.Sync(context.Background(), 0)
			if err != nil {
				return err
			}
			live := 0
			for _, it := range res.Items {
				if !it.Deleted {
					live++
				}
			}
			a.Sec.Last = res.Revision
			if err := a.saveSecretsOnly(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Synced %d item(s) (%d deleted), revision=%d\n", live, len(res.Items)-live, res.Revision)
			return nil
		},
	}
}

func newGenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a random password",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := pwgen.Options{
				Length:     getInt(cmd, "length"),
				Lower:      !getBool(cmd, "no-lower"),
				Upper:      !getBool(cmd, "no-upper"),
				Digits:     !getBool(cmd, "no-digits"),
				Symbols:    !getBool(cmd, "no-symbols"),
				ExcludeAmb: !getBool(cmd, "allow-ambiguous"),
			}
			count := getInt(cmd, "count")
			for i := 0; i < count; i++ {
				pw, err := pwgen.Generate(opts)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), pw)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.Int("length", 20, "password length")
	f.Int("count", 1, "number of passwords")
	f.Bool("no-lower", false, "exclude lowercase letters")
	f.Bool("no-upper", false, "exclude uppercase letters")
	f.Bool("no-digits", false, "exclude digits")
	f.Bool("no-symbols", false, "exclude symbols")
	f.Bool("allow-ambiguous", false, "allow visually ambiguous characters")
	return cmd
}

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export decrypted items",
		RunE:  runExport,
	}
	f := cmd.Flags()
	f.String("format", "json", "output format: json|csv")
	f.String("output", "", "output file (default stdout)")
	return cmd
}

func runExport(cmd *cobra.Command, _ []string) error {
	a, err := newApp(cmd)
	if err != nil {
		return err
	}
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	items, _, err := a.syncDecrypted(context.Background())
	if err != nil {
		return err
	}
	var itemsOut []vault.Item
	for _, di := range items {
		it, err := vault.Unmarshal(di.Plain)
		if err != nil {
			return err
		}
		itemsOut = append(itemsOut, it)
	}

	var w io.Writer = cmd.OutOrStdout()
	if out := getFlag(cmd, "output"); out != "" {
		f, err := os.OpenFile(expandPath(out), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	switch strings.ToLower(getFlag(cmd, "format")) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		// #nosec G117 -- export intentionally contains decrypted credentials.
		return enc.Encode(itemsOut)
	case "csv":
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"name", "username", "password", "url", "notes", "type"}); err != nil {
			return err
		}
		for _, it := range itemsOut {
			if err := cw.Write([]string{it.Name, it.Username, it.Password, it.PrimaryURL(), it.Notes, it.Type}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	default:
		return errors.New("unsupported format (use json or csv)")
	}
}

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import items from CSV or JSON",
		Args:  cobra.ExactArgs(1),
		RunE:  runImport,
	}
	cmd.Flags().String("vault", "", "target vault id")
	cmd.Flags().String("format", "", "input format: csv|json (default: infer from extension)")
	return cmd
}

func runImport(cmd *cobra.Command, args []string) error {
	a, err := newApp(cmd)
	if err != nil {
		return err
	}
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	data, err := os.ReadFile(expandPath(args[0]))
	if err != nil {
		return err
	}
	format := getFlag(cmd, "format")
	if format == "" {
		if strings.HasSuffix(strings.ToLower(args[0]), ".csv") {
			format = "csv"
		} else {
			format = "json"
		}
	}
	var items []vault.Item
	switch format {
	case "json":
		if err := json.Unmarshal(data, &items); err != nil {
			return fmt.Errorf("parse JSON: %w", err)
		}
	case "csv":
		items, err = parseCSV(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported format (use json or csv)")
	}

	vk, vaultID, alg, err := a.vaultKeyFor(getFlag(cmd, "vault"))
	if err != nil {
		return err
	}
	ctx := context.Background()
	now := a.now()
	imported := 0
	for _, it := range items {
		if it.ID == "" {
			it.ID = newUUID()
		}
		it.Type = orDefault(it.Type, vault.TypeLogin)
		if it.CreatedAt.IsZero() {
			it.CreatedAt = now
		}
		it.UpdatedAt = now
		plain, err := it.Marshal()
		if err != nil {
			return err
		}
		blob, err := crypto.SealItemWithVaultKey(alg, vk, vaultID, it.ID, plain)
		if err != nil {
			return err
		}
		if _, err := a.Client.CreateItem(ctx, vaultID, it.ID, blob); err != nil {
			return fmt.Errorf("import %q: %w", it.Name, err)
		}
		imported++
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Imported %d item(s)\n", imported)
	return nil
}

func parseCSV(data []byte) ([]vault.Item, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	header := map[string]int{}
	for i, h := range rows[0] {
		header[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(row []string, key string) string {
		if idx, ok := header[key]; ok && idx < len(row) {
			return row[idx]
		}
		return ""
	}
	var out []vault.Item
	for _, row := range rows[1:] {
		name := get(row, "name")
		if name == "" {
			continue
		}
		it := vault.Item{
			Type:     orDefault(get(row, "type"), vault.TypeLogin),
			Name:     name,
			Username: get(row, "username"),
			Password: get(row, "password"),
			Notes:    get(row, "notes"),
		}
		if u := get(row, "url"); u != "" {
			it.URLs = []string{u}
		}
		out = append(out, it)
	}
	return out, nil
}

func newPasswordCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "password",
		Short: "Change the master password (re-wraps vault keys)",
		RunE:  runChangePassword,
	}
}

func runChangePassword(cmd *cobra.Command, _ []string) error {
	a, err := newApp(cmd)
	if err != nil {
		return err
	}
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	ctx := context.Background()
	email := a.Cfg.Email
	if email == "" {
		return errors.New("no account email configured")
	}
	kdfWire, err := a.Client.KDF(ctx, email)
	if err != nil {
		return err
	}
	oldParams, err := kdfWire.ToCrypto()
	if err != nil {
		return err
	}
	oldPw, err := promptSecret("Current master password: ")
	if err != nil {
		return err
	}
	_, _, oldKEK, err := deriveKeys(oldPw, oldParams)
	if err != nil {
		return err
	}
	// Verify the current password by re-unwrapping every cached vault.
	if err := a.unwrapVaults(ctx, oldKEK); err != nil {
		return err
	}
	newPw, err := promptNewPassword()
	if err != nil {
		return err
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	var saltArr [16]byte
	copy(saltArr[:], salt)
	newParams, err := crypto.ParamsForProfile(crypto.ProfileInteractive, saltArr)
	if err != nil {
		return err
	}
	_, newAuthKey, newKEK, err := deriveKeys(newPw, newParams)
	if err != nil {
		return err
	}
	vaults, err := a.Client.ListVaults(ctx)
	if err != nil {
		return err
	}
	var rewraps []client.VaultKeyInput
	var newCache []vaultSecret
	for _, v := range vaults {
		vk, _, _, err := a.vaultKeyFor(v.ID)
		if err != nil {
			return err
		}
		prot, err := crypto.WrapVaultKey(newKEK, v.Alg, newParams, v.ID, vk)
		if err != nil {
			return err
		}
		rewraps = append(rewraps, client.VaultKeyInput{
			ID: v.ID, Alg: v.Alg, ProtectedVaultKey: base64.StdEncoding.EncodeToString(prot),
		})
		newCache = append(newCache, vaultSecret{ID: v.ID, Alg: v.Alg, Key: base64.StdEncoding.EncodeToString(vk[:])})
	}
	if err := a.Client.ChangePassword(ctx, newParams, newAuthKey, rewraps); err != nil {
		return err
	}
	a.Sec.KDF = toSecret(kdfWire)
	a.Sec.KDF.M, a.Sec.KDF.T, a.Sec.KDF.P = newParams.M, newParams.T, newParams.P
	a.Sec.KDF.Salt = base64.StdEncoding.EncodeToString(newParams.Salt[:])
	a.Sec.Vaults = newCache
	if err := a.saveSecretsOnly(); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Master password changed")
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
