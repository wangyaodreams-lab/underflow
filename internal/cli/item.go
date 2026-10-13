package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/pwgen"
	"github.com/wangyaodreams-lab/underflow/internal/vault"
)

func newItemCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "item",
		Short: "Manage vault items",
	}
	cmd.AddCommand(newItemAddCmd(), newItemListCmd(), newItemGetCmd(), newItemEditCmd(), newItemRmCmd())
	return cmd
}

func newItemAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new item",
		RunE:  runItemAdd,
	}
	f := cmd.Flags()
	f.String("name", "", "item name (required)")
	f.String("username", "", "username")
	f.String("url", "", "primary URL")
	f.String("notes", "", "notes")
	f.String("type", vault.TypeLogin, "item type: login|note|card|identity")
	f.String("vault", "", "vault id (defaults to the only unlocked vault)")
	f.Bool("generate", false, "generate a random password")
	f.Int("length", 20, "generated password length")
	f.Bool("password-stdin", false, "read the password from stdin")
	f.Bool("no-password", false, "do not set a password")
	return cmd
}

func runItemAdd(cmd *cobra.Command, _ []string) error {
	a, err := newApp(cmd)
	if err != nil {
		return err
	}
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	name := getFlag(cmd, "name")
	if name == "" {
		return errors.New("--name is required")
	}
	password, err := a.resolveNewPassword(cmd, getFlag(cmd, "type"))
	if err != nil {
		return err
	}
	vk, vaultID, alg, err := a.vaultKeyFor(getFlag(cmd, "vault"))
	if err != nil {
		return err
	}
	now := a.now()
	item := vault.Item{
		ID: newUUID(), Type: getFlag(cmd, "type"), Name: name,
		Username: getFlag(cmd, "username"), Password: password,
		Notes: getFlag(cmd, "notes"), CreatedAt: now, UpdatedAt: now,
	}
	if u := getFlag(cmd, "url"); u != "" {
		item.URLs = []string{u}
	}
	plain, err := item.Marshal()
	if err != nil {
		return err
	}
	blob, err := crypto.SealItemWithVaultKey(alg, vk, vaultID, item.ID, plain)
	if err != nil {
		return err
	}
	created, err := a.Client.CreateItem(context.Background(), vaultID, item.ID, blob)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Added %q (%s) revision=%d\n", item.Name, item.ID, created.Revision)
	return nil
}

func newItemListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List items",
		RunE:  runItemList,
	}
	cmd.Flags().Bool("show-passwords", false, "include passwords")
	return cmd
}

func runItemList(cmd *cobra.Command, _ []string) error {
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
	show := getBool(cmd, "show-passwords")
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
	if show {
		fmt.Fprintln(tw, "NAME\tUSERNAME\tPASSWORD\tID")
	} else {
		fmt.Fprintln(tw, "NAME\tUSERNAME\tID")
	}
	for _, di := range items {
		it, err := vault.Unmarshal(di.Plain)
		if err != nil {
			return err
		}
		if show {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", it.Name, it.Username, it.Password, it.ID)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", it.Name, it.Username, it.ID)
		}
	}
	return tw.Flush()
}

func newItemGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <id|name>",
		Short: "Show an item",
		Args:  cobra.ExactArgs(1),
		RunE:  runItemGet,
	}
	cmd.Flags().Bool("show", false, "reveal the password")
	return cmd
}

func runItemGet(cmd *cobra.Command, args []string) error {
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
	di, err := findItem(items, args[0])
	if err != nil {
		return err
	}
	it, err := vault.Unmarshal(di.Plain)
	if err != nil {
		return err
	}
	pw := it.Password
	if !getBool(cmd, "show") && pw != "" {
		pw = "********"
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "id:       %s\n", it.ID)
	fmt.Fprintf(out, "name:     %s\n", it.Name)
	fmt.Fprintf(out, "type:     %s\n", it.Type)
	if it.Username != "" {
		fmt.Fprintf(out, "username: %s\n", it.Username)
	}
	if it.Password != "" {
		fmt.Fprintf(out, "password: %s\n", pw)
	}
	if u := it.PrimaryURL(); u != "" {
		fmt.Fprintf(out, "url:      %s\n", u)
	}
	if it.Notes != "" {
		fmt.Fprintf(out, "notes:    %s\n", it.Notes)
	}
	fmt.Fprintf(out, "revision: %d\n", di.Item.Revision)
	return nil
}

func newItemEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <id|name>",
		Short: "Edit an item",
		Args:  cobra.ExactArgs(1),
		RunE:  runItemEdit,
	}
	f := cmd.Flags()
	f.String("name", "", "new name")
	f.String("username", "", "new username")
	f.String("url", "", "new primary URL")
	f.String("notes", "", "new notes")
	f.Bool("generate", false, "generate a new password")
	f.Int("length", 20, "generated password length")
	f.Bool("password-stdin", false, "read the new password from stdin")
	return cmd
}

func runItemEdit(cmd *cobra.Command, args []string) error {
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
	di, err := findItem(items, args[0])
	if err != nil {
		return err
	}
	it, err := vault.Unmarshal(di.Plain)
	if err != nil {
		return err
	}
	changed := false
	if cmd.Flags().Changed("name") {
		it.Name = getFlag(cmd, "name")
		changed = true
	}
	if cmd.Flags().Changed("username") {
		it.Username = getFlag(cmd, "username")
		changed = true
	}
	if cmd.Flags().Changed("url") {
		it.URLs = []string{getFlag(cmd, "url")}
		changed = true
	}
	if cmd.Flags().Changed("notes") {
		it.Notes = getFlag(cmd, "notes")
		changed = true
	}
	newPw, err := a.maybeEditPassword(cmd)
	if err != nil {
		return err
	}
	if newPw != "" {
		if it.Password != "" && it.Password != newPw {
			it.PasswordHistory = append(it.PasswordHistory, vault.PasswordEntry{Password: it.Password, ChangedAt: a.now()})
		}
		it.Password = newPw
		changed = true
	}
	if !changed {
		return errors.New("no changes requested")
	}
	it.UpdatedAt = a.now()
	plain, err := it.Marshal()
	if err != nil {
		return err
	}
	vk, vaultID, alg, err := a.vaultKeyFor(di.VaultID)
	if err != nil {
		return err
	}
	blob, err := crypto.SealItemWithVaultKey(alg, vk, vaultID, it.ID, plain)
	if err != nil {
		return err
	}
	updated, err := a.Client.UpdateItem(context.Background(), vaultID, it.ID, blob, di.Item.Revision)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Updated %q revision=%d\n", it.Name, updated.Revision)
	return nil
}

func newItemRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id|name>",
		Short: "Delete an item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			di, err := findItem(items, args[0])
			if err != nil {
				return err
			}
			if _, err := a.Client.DeleteItem(context.Background(), di.VaultID, di.Item.ID, di.Item.Revision); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s\n", di.Item.ID)
			return nil
		},
	}
}

// --- helpers ---

func (a *App) resolveNewPassword(cmd *cobra.Command, itemType string) (string, error) {
	if itemType != vault.TypeLogin {
		return "", nil
	}
	switch {
	case getBool(cmd, "no-password"):
		return "", nil
	case getBool(cmd, "generate"):
		return pwgen.Generate(pwgen.Options{Length: getInt(cmd, "length"), Lower: true, Upper: true, Digits: true, Symbols: true, ExcludeAmb: true})
	case getBool(cmd, "password-stdin"):
		line, err := readLine()
		if err != nil {
			return "", err
		}
		return line, nil
	default:
		return promptSecret("Password (leave blank to generate): ")
	}
}

func (a *App) maybeEditPassword(cmd *cobra.Command) (string, error) {
	switch {
	case getBool(cmd, "generate"):
		return pwgen.Generate(pwgen.Options{Length: getInt(cmd, "length"), Lower: true, Upper: true, Digits: true, Symbols: true, ExcludeAmb: true})
	case getBool(cmd, "password-stdin"):
		return readLine()
	default:
		return "", nil
	}
}

func findItem(items []decryptedItem, query string) (decryptedItem, error) {
	// Exact id match first.
	for _, di := range items {
		if di.Item.ID == query {
			return di, nil
		}
	}
	// Then case-insensitive name match.
	var match *decryptedItem
	for i := range items {
		it, err := vault.Unmarshal(items[i].Plain)
		if err != nil {
			continue
		}
		if strings.EqualFold(it.Name, query) {
			if match != nil {
				return decryptedItem{}, fmt.Errorf("multiple items named %q; use the id", query)
			}
			match = &items[i]
		}
	}
	if match == nil {
		return decryptedItem{}, fmt.Errorf("no item matching %q", query)
	}
	return *match, nil
}

func getInt(cmd *cobra.Command, name string) int {
	if f := cmd.Flags().Lookup(name); f != nil {
		v, _ := cmd.Flags().GetInt(name)
		return v
	}
	return 0
}
