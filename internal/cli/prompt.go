package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/spf13/cobra"
)

// getFlag reads a flag from the command or the root's persistent set.
func getFlag(cmd *cobra.Command, name string) string {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f.Value.String()
	}
	if f := cmd.Root().PersistentFlags().Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

func getBool(cmd *cobra.Command, name string) bool {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f.Value.String() == "true"
	}
	if f := cmd.Root().PersistentFlags().Lookup(name); f != nil {
		return f.Value.String() == "true"
	}
	return false
}

func ensureDir(dir string) error {
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

// promptSecret reads a secret without echoing when stdin is a terminal.
func promptSecret(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	line, err := readLine()
	if err != nil {
		return "", err
	}
	return line, nil
}

// stdinReader is shared across all reads so that buffered stdin (pipelines,
// heredocs) is not lost between calls. It is re-created if os.Stdin changes
// (which tests rely on).
var (
	stdinReader *bufio.Reader
	stdinFD     uintptr
)

func stdinBuf() *bufio.Reader {
	fd := os.Stdin.Fd()
	if stdinReader == nil || stdinFD != fd {
		stdinReader = bufio.NewReader(os.Stdin)
		stdinFD = fd
	}
	return stdinReader
}

func readLine() (string, error) {
	line, err := stdinBuf().ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	return readLine()
}

// promptNewPassword asks twice and enforces a minimum length.
func promptNewPassword() (string, error) {
	p1, err := promptSecret("Master password: ")
	if err != nil {
		return "", err
	}
	if len(p1) < 12 {
		return "", errors.New("master password must be at least 12 characters")
	}
	p2, err := promptSecret("Confirm master password: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("passwords do not match")
	}
	return p1, nil
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "device"
	}
	return hex.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
