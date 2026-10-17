// Package cli implements the Underflow command-line interface.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wangyaodreams-lab/underflow/internal/version"
)

// NewRootCmd builds the Underflow command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "underflow",
		Short:         "Underflow is a zero-knowledge password manager",
		Long:          "Underflow stores passwords encrypted on the client. The server never sees plaintext or your master password.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.PersistentFlags().String("server", "", "Underflow server URL (overrides config)")
	root.PersistentFlags().String("email", "", "account email (overrides config)")
	root.PersistentFlags().String("config-dir", "", "configuration directory (default ~/.config/underflow)")

	root.AddCommand(
		newServeCmd(),
		newLauncherCmd(),
		newRegisterCmd(),
		newLoginCmd(),
		newUnlockCmd(),
		newLockCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
		newItemCmd(),
		newSyncCmd(),
		newGenCmd(),
		newExportCmd(),
		newImportCmd(),
		newPasswordCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Underflow version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version.Version)
			return nil
		},
	}
}
