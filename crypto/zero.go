package crypto

import "runtime"

// Zero overwrites b with zero bytes.
//
// This is best-effort: the Go garbage collector may have already copied secret
// bytes elsewhere. Callers should still zero buffers as early as possible.
//
//go:noinline
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroKey zeroes a fixed-size key buffer.
func ZeroKey(k *[32]byte) {
	if k == nil {
		return
	}
	for i := range k {
		k[i] = 0
	}
	runtime.KeepAlive(k)
}
