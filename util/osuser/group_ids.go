// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osuser

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"tailscale.com/version/distro"
)

// GetGroupIds returns the list of group IDs that the user is a member of, or
// an error. It will first try to use the 'id' command to get the group IDs,
// and if that fails, it will fall back to the user.GroupIds method.
func GetGroupIds(user *user.User) ([]string, error) {
	if runtime.GOOS == "plan9" {
		return nil, nil
	}

	// We are hardcoding for shell user
	if runtime.GOOS == "android" {
		return []string{
			"1002", // bluetooth
			"1005", // audio
			"1007", // log
			"1013", // media
			"1015", // sdcard_rw
			"1024", // mtp
			"1065", // reserved_disk
			"1077", // external_storage
			"1078", // ext_data_rw
			"1079", // ext_data_obb
			"3001", // net_bt_admin
			"3002", // net_bt
			"3003", // inet
			"3007", // net_bt_acct
			"3010", // wakelock
			"3011", // uhid
			"3013", // ???
			"9997", // everybody
		}, nil
	}

	if runtime.GOOS != "linux" {
		return user.GroupIds()
	}

	if distro.Get() == distro.Gokrazy {
		// Gokrazy is a single-user appliance with ~no userspace.
		// There aren't users to look up (no /etc/passwd, etc)
		// so rather than fail below, just hardcode root.
		// TODO(bradfitz): fix os/user upstream instead?
		return []string{"0"}, nil
	}

	if ids, err := getGroupIdsWithId(user.Username); err == nil {
		return ids, nil
	}
	return user.GroupIds()
}

func getGroupIdsWithId(usernameOrUID string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "id", "-Gz", usernameOrUID)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running 'id' command: %w", err)
	}
	return parseGroupIds(out), nil
}

func parseGroupIds(cmdOutput []byte) []string {
	return strings.Split(strings.Trim(string(cmdOutput), "\n\x00"), "\x00")
}
