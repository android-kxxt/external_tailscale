// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import "strings"

func isAndroidAppContext(label string) bool {
	// libselinux LEVELFROM_USER assigns c512,c768 to Android user 0.
	// Compare the entire context: a domain-name substring would accept other
	// Android users or an unrelated type containing "tailscale_app".
	return strings.TrimRight(label, "\x00") == "u:r:tailscale_app:s0:c512,c768"
}
