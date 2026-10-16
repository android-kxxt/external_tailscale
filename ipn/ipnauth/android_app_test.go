// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package ipnauth

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
	"tailscale.com/safesocket"
)

func TestAndroidSocketIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailscaled.sock")
	ln, err := safesocket.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0666 {
		t.Fatalf("socket permissions = %04o; want 0666 with peer authorization", fi.Mode().Perm())
	}
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ci, err := GetConnIdentity(t.Logf, server)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Creds() == nil {
		t.Fatal("missing Android peer credentials")
	}
	if uid, ok := ci.Creds().UserID(); !ok || uid != strconv.Itoa(os.Getuid()) {
		t.Fatalf("peer UID = %q, %v; want %d", uid, ok, os.Getuid())
	}
	raw, err := server.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var label string
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		label, sockErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_PEERSEC)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	if label == "" {
		t.Fatal("empty Android peer security context")
	}
	t.Logf("peer security context: %s", label)
	if got, want := ci.IsAndroidApp(), isAndroidAppContext(label); got != want {
		t.Fatalf("IsAndroidApp = %v; want %v for %q", got, want, label)
	}
}
