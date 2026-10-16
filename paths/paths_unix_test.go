// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !wasm && !plan9 && !tamago

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateDirPermissions(t *testing.T) {
	for _, tt := range []struct {
		name, goos, path string
		want             os.FileMode
	}{
		{"android-system", "android", "/data/tailscale", 0711},
		{"android-system-cleaned", "android", "/data/tailscale/", 0711},
		{"android-custom", "android", "/data/private/tailscale", 0700},
		{"linux", "linux", "/data/tailscale", 0700},
		{"darwin", "darwin", "/data/tailscale", 0700},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mode := stateDirPermForOS(tt.path, tt.goos)
			if mode != tt.want {
				t.Fatalf("state directory mode = %04o; want %04o", mode, tt.want)
			}
			dir := filepath.Join(t.TempDir(), "tailscale")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(dir, "tailscaled.state")
			if err := os.WriteFile(state, []byte("private state"), 0600); err != nil {
				t.Fatal(err)
			}
			// Exercise migration from old init permissions and repeated daemon
			// startups: the directory must stay traversable on Android.
			for _, initial := range []os.FileMode{0700, 0770, 0711} {
				if err := os.Chmod(dir, initial); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					if err := ensureStateDirMode(dir, mode); err != nil {
						t.Fatal(err)
					}
					fi, err := os.Stat(dir)
					if err != nil {
						t.Fatal(err)
					}
					if fi.Mode().Perm() != tt.want {
						t.Fatalf("directory mode = %04o; want %04o", fi.Mode().Perm(), tt.want)
					}
				}
			}
			fi, err := os.Stat(state)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0600 {
				t.Fatalf("state mode = %04o; want 0600", fi.Mode().Perm())
			}
		})
	}
}
