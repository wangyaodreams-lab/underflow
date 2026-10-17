package cli

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestFreeListenAddrKeepsFreePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := freeListenAddr(addr)
	if err != nil {
		t.Fatalf("freeListenAddr: %v", err)
	}
	if got != addr {
		t.Errorf("freeListenAddr = %q, want the requested free port %q", got, addr)
	}
}

// A busy default port must not stop the user: the launcher moves to the next
// free one instead of failing.
func TestFreeListenAddrMovesPastBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	busy := ln.Addr().String()
	_, busyPort, _ := net.SplitHostPort(busy)
	port, _ := strconv.Atoi(busyPort)

	got, err := freeListenAddr(busy)
	if err != nil {
		t.Fatalf("freeListenAddr: %v", err)
	}
	if got == busy {
		t.Fatalf("freeListenAddr returned the busy address %q", busy)
	}
	host, gotPort, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("result %q is not host:port: %v", got, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host = %q, want the requested host", host)
	}
	n, err := strconv.Atoi(gotPort)
	if err != nil || n <= port || n > port+20 {
		t.Errorf("port = %v, want a nearby free port above %d", gotPort, port)
	}
}

func TestFreeListenAddrRejectsGarbage(t *testing.T) {
	for _, addr := range []string{"", "127.0.0.1", "127.0.0.1:not-a-port", "127.0.0.1:99999", ":::"} {
		if _, err := freeListenAddr(addr); err == nil {
			t.Errorf("freeListenAddr(%q) should fail", addr)
		}
	}
}

// The launcher command must expose its own listen address without colliding
// with the server's default port.
func TestLauncherCmdDefaults(t *testing.T) {
	cmd := newLauncherCmd()
	addr := getFlag(cmd, "addr")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("default --addr %q is not host:port: %v", addr, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("default host = %q, want loopback", host)
	}
	if port == "8080" {
		t.Error("the launcher must not default to the server's port 8080")
	}
	if !getBool(cmd, "open") {
		t.Error("the launcher should open a browser by default")
	}
	if !strings.Contains(cmd.Long, "UF_") {
		t.Error("the command help should mention the UF_* contract it controls")
	}
}
