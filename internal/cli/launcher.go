package cli

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/wangyaodreams-lab/underflow/internal/launcher"
)

// defaultLauncherAddr keeps the launcher off the server's usual port so both
// can be reached at once.
const defaultLauncherAddr = "127.0.0.1:8090"

func newLauncherCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "launcher",
		Short: "Open a local web UI to configure and start the server",
		Long: `Serve a local web interface for the server's startup parameters.

The launcher writes the same UF_* environment contract that ` + "`underflow serve`" + `
reads, validates the settings against the server's own rules, then supervises
the server process and streams its log output back to the page.

It binds to loopback only and is meant for local use and development.`,
		RunE: runLauncher,
	}
	f := cmd.Flags()
	f.String("addr", defaultLauncherAddr, "launcher listen address")
	f.String("state-dir", "", "directory for launcher.json (default ~/.config/underflow)")
	f.String("work-dir", "", "working directory for the server (default: current directory)")
	f.String("binary", "", "underflow binary to spawn (default: this executable)")
	f.Bool("open", true, "open the launcher in a browser")
	return cmd
}

func runLauncher(cmd *cobra.Command, _ []string) error {
	workDir := getFlag(cmd, "work-dir")
	if workDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		workDir = wd
	}

	addr, err := freeListenAddr(getFlag(cmd, "addr"))
	if err != nil {
		return err
	}

	srv, err := launcher.NewServer(launcher.Options{
		WorkDir:  workDir,
		StateDir: getFlag(cmd, "state-dir"),
		Binary:   getFlag(cmd, "binary"),
		Addr:     addr,
	})
	if err != nil {
		return err
	}

	url := "http://" + addr
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Underflow launcher: %s\n", url)
	fmt.Fprintf(out, "  server work dir: %s\n", workDir)
	fmt.Fprintf(out, "  spawning:        %s serve\n", srv.Binary())
	fmt.Fprintln(out, "Press Ctrl+C to stop the launcher (the server is stopped with it).")

	if getBool(cmd, "open") {
		if err := launcher.OpenBrowser(url); err != nil {
			fmt.Fprintf(out, "could not open a browser automatically: %v\n", err)
		}
	}

	// Stop the supervised server when the launcher exits so no orphan keeps
	// holding the port.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		_ = srv.Manager().Stop()
		os.Exit(0)
	}()

	return srv.Serve(addr)
}

// freeListenAddr returns addr if it can be bound, otherwise the next free port
// on the same host. A missing favourite port should not stop the user.
func freeListenAddr(addr string) (string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid --addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", fmt.Errorf("invalid --addr %q: bad port", addr)
	}
	for i := 0; i < 20; i++ {
		candidate := net.JoinHostPort(host, strconv.Itoa(port+i))
		ln, err := net.Listen("tcp", candidate)
		if err != nil {
			continue
		}
		_ = ln.Close()
		return candidate, nil
	}
	return "", fmt.Errorf("no free port available near %s", addr)
}
