// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import "testing"

func TestAndroidAppContext(t *testing.T) {
	for _, tt := range []struct {
		label string
		want  bool
	}{
		{"u:r:tailscale_app:s0:c512,c768", true},
		{"u:r:tailscale_app:s0:c512,c768\x00", true},
		{"u:r:tailscale_app:s0:c513,c768", false},
		{"u:r:tailscale_app:s0", false},
		{"u:r:untrusted_app:s0:c512,c768", false},
		{"u:r:platform_app:s0:c512,c768", false},
		{"u:r:fake_tailscale_app:s0:c512,c768", false},
		{"", false},
	} {
		if got := isAndroidAppContext(tt.label); got != tt.want {
			t.Errorf("isAndroidAppContext(%q) = %v, want %v", tt.label, got, tt.want)
		}
	}
}
