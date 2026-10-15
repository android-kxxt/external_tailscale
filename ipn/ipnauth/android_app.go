// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package ipnauth

import (
	"net"

	"golang.org/x/sys/unix"
)

// IsAndroidApp reports whether this Unix socket's peer is the platform-signed
// Tailscale UI. Android assigns the domain using the package name AND signing
// identity in seapp_contexts. Never trust a UID supplied in an HTTP header or
// grant access to every app signed with the platform key.
func (ci *ConnIdentity) IsAndroidApp() bool {
	conn, ok := ci.conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var label string
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		label, sockErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_PEERSEC)
	})
	if err != nil || sockErr != nil {
		return false
	}
	// Only the primary Android user controls the system-wide daemon. Secondary
	// users have a different MLS category; isolated processes have another domain.
	return isAndroidAppContext(label)
}
