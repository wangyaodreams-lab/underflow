// Package pwgen generates cryptographically secure passwords.
package pwgen

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

const (
	lower   = "abcdefghijkmnopqrstuvwxyz"
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digits  = "23456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.?/"
	similar = "il1Lo0O"
)

// Options configures password generation.
type Options struct {
	Length     int
	Lower      bool
	Upper      bool
	Digits     bool
	Symbols    bool
	ExcludeAmb bool
}

// DefaultOptions returns sensible defaults (20 chars, all classes).
func DefaultOptions() Options {
	return Options{Length: 20, Lower: true, Upper: true, Digits: true, Symbols: true, ExcludeAmb: true}
}

// Generate returns a random password satisfying opts.
//
// It guarantees at least one character from every enabled class, then pads with
// uniformly chosen characters from the combined alphabet.
func Generate(opts Options) (string, error) {
	var classes []string
	if opts.Lower {
		classes = append(classes, lower)
	}
	if opts.Upper {
		classes = append(classes, upper)
	}
	if opts.Digits {
		classes = append(classes, digits)
	}
	if opts.Symbols {
		classes = append(classes, symbols)
	}
	if len(classes) == 0 {
		return "", errors.New("pwgen: no character classes enabled")
	}
	if opts.Length < len(classes) {
		return "", errors.New("pwgen: length shorter than enabled classes")
	}

	alphabet := strings.Join(classes, "")
	if opts.ExcludeAmb {
		alphabet = stripAny(alphabet, similar)
		for i := range classes {
			classes[i] = stripAny(classes[i], similar)
		}
	}

	runes := []rune(alphabet)
	out := make([]rune, 0, opts.Length)
	// One guaranteed character per enabled class.
	for _, c := range classes {
		r, err := pick([]rune(c))
		if err != nil {
			return "", err
		}
		out = append(out, r)
	}
	for len(out) < opts.Length {
		r, err := pick(runes)
		if err != nil {
			return "", err
		}
		out = append(out, r)
	}
	shuffle(out)
	return string(out), nil
}

func pick(set []rune) (rune, error) {
	if len(set) == 0 {
		return 0, errors.New("pwgen: empty character set")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

// shuffle performs a Fisher-Yates shuffle using crypto/rand.
func shuffle(r []rune) {
	for i := len(r) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		j := int(n.Int64())
		r[i], r[j] = r[j], r[i]
	}
}

func stripAny(s, remove string) string {
	var b strings.Builder
	for _, r := range s {
		if !strings.ContainsRune(remove, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
