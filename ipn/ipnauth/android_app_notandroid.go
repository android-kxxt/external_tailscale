// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package ipnauth

func (ci *ConnIdentity) IsAndroidApp() bool { return false }
