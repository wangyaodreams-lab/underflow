// Command underflow is the single binary that provides both the web/API server
// and the command-line client.
package main

import (
	"fmt"
	"os"

	"github.com/wangyaodreams-lab/underflow/internal/cli"
)

func main() {
	// The root command has SilenceErrors set, so report the failure here.
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "underflow: %v\n", err)
		os.Exit(1)
	}
}
