// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !wasm && !plan9 && !tamago

package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
	"tailscale.com/version/distro"
)

func init() {
	stateFileFunc = stateFileUnix
	ensureStateDirPerms = ensureStateDirPermsUnix
}

func statePath() string {
	if runtime.GOOS == "linux" && distro.Get() == distro.JetKVM {
		return "/userdata/tailscale/var/tailscaled.state"
	}
	switch runtime.GOOS {
	case "linux", "illumos", "solaris":
		return "/var/lib/tailscale/tailscaled.state"
	case "freebsd", "openbsd":
		return "/var/db/tailscale/tailscaled.state"
	case "darwin":
		return "/Library/Tailscale/tailscaled.state"
	case "aix":
		return "/var/tailscale/tailscaled.state"
	case "android":
		return "/data/tailscale/tailscaled.state"
	default:
		return ""
	}
}

func stateFileUnix() string {
	if distro.Get() == distro.Gokrazy {
		return "/perm/tailscaled/tailscaled.state"
	}
	path := statePath()
	if path == "" {
		return ""
	}

	try := path
	for range 3 { // check writability of the file, /var/lib/tailscale, and /var/lib
		err := unix.Access(try, unix.O_RDWR)
		if err == nil {
			return path
		}
		try = filepath.Dir(try)
	}

	if os.Getuid() == 0 {
		return ""
	}

	// For non-root users, fall back to $XDG_DATA_HOME/tailscale/*.
	return filepath.Join(xdgDataHome(), "tailscale", "tailscaled.state")
}

func xdgDataHome() string {
	if e := os.Getenv("XDG_DATA_HOME"); e != "" {
		return e
	}
	return filepath.Join(os.Getenv("HOME"), ".local/share")
}

func ensureStateDirPermsUnix(dir string) error {
	return ensureStateDirMode(dir, stateDirPermForOS(dir, runtime.GOOS))
}

func stateDirPermForOS(dir, goos string) os.FileMode {
	// Android keeps the LocalAPI socket in the default state directory. Allow
	// traversal to that socket, but not directory listing or modification.
	// State files remain 0600; SELinux and SO_PEERSEC restrict socket access.
	// This must agree with init: NewFileStore reapplies permissions at startup.
	if goos == "android" && filepath.Clean(dir) == "/data/tailscale" {
		return 0711
	}
	return 0700
}

func ensureStateDirMode(dir string, perm os.FileMode) error {
	if filepath.Base(dir) != "tailscale" {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("expected %q to be a directory; is %v", dir, fi.Mode())
	}
	if fi.Mode().Perm() == perm {
		// Already correct.
		return nil
	}
	return os.Chmod(dir, perm)
}
