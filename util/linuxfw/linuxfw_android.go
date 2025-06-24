// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

// Package linuxfw returns the kind of firewall being used by the kernel.
package linuxfw

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tailscale/netlink"
	"tailscale.com/types/logger"
)

// MatchDecision is the decision made by the firewall for a packet matched by a rule.
// It is used to decide whether to accept or masquerade a packet in addMatchSubnetRouteMarkRule.
type MatchDecision int

const (
	Accept MatchDecision = iota
	Masq
)

type FWModeNotSupportedError struct {
	Mode FirewallMode
	Err  error
}

func (e FWModeNotSupportedError) Error() string {
	return fmt.Sprintf("firewall mode %q not supported: %v", e.Mode, e.Err)
}

func (e FWModeNotSupportedError) Is(target error) bool {
	_, ok := target.(FWModeNotSupportedError)
	return ok
}

func (e FWModeNotSupportedError) Unwrap() error {
	return e.Err
}

type FirewallMode string

const (
	FirewallModeIPTables FirewallMode = "iptables"
	FirewallModeNfTables FirewallMode = "nftables"
)

// The following bits are added to packet marks for Tailscale use.
//
// We tried to pick bits sufficiently out of the way that it's
// unlikely to collide with existing uses. We have 4 bytes of mark
// bits to play with. We leave the lower byte alone on the assumption
// that sysadmins would use those. Kubernetes uses a few bits in the
// second byte, so we steer clear of that too.
//
// AOSP's code for Fwmark allocation is
// https://android.googlesource.com/platform/system/netd/+/master/include/Fwmark.h
//
//	struct {
//	    unsigned netId          : 16;
//	    bool explicitlySelected :  1;
//	    bool protectedFromVpn   :  1;
//	    Permission permission   :  2;
//	    bool uidBillingDone     :  1;
//	    unsigned reserved       :  8;
//	    unsigned vendor         :  2;  // reserved for vendor
//	    bool ingress_cpu_wakeup :  1;  // reserved for config_networkWakeupPacketMark/Mask
//	};
//
// The lower 0-20 bits are already allocated.
// Bit 21-28 is currently unused.
// In the future,AOSP is likely to use some of the lower bits of the 8 bits.
// Tailscale currently reserves 8 bits for its own usage but only uses 4 bits.
// For max compatibility with future AOSP development, we will use the higher 4 bits
// of the reserved part.
//
// The constants are in the iptables/iproute2 string format for
// matching and setting the bits, so they can be directly embedded in
// commands.
const (
	// The mask for reading/writing the 'firewall mask' bits on a packet.
	// See the comment on the const block on why we only use the third byte.
	//
	// We claim bits 25:28 entirely.
	TailscaleFwmarkMask    = "0x1e0c0000"
	TailscaleFwmarkMaskNum = 0x1e0c0000

	// Packet is from Tailscale and to a subnet route destination, so
	// is allowed to be routed through this machine.
	TailscaleSubnetRouteMark    = "0x80c0000"
	TailscaleSubnetRouteMarkNum = 0x80c0000

	// Packet was originated by tailscaled itself, and must not be
	// routed over the Tailscale network.
	TailscaleBypassMark    = "0x10000000"
	TailscaleBypassMarkNum = 0x10000000
)

// getTailscaleFwmarkMaskNeg returns the negation of TailscaleFwmarkMask in bytes.
func getTailscaleFwmarkMaskNeg() []byte {
	return []byte{0xe1, 0xf3, 0xff, 0xff}
}

// getTailscaleFwmarkMask returns the TailscaleFwmarkMask in bytes.
func getTailscaleFwmarkMask() []byte {
	return []byte{0x1e, 0x0c, 0x00, 0x00}
}

// getTailscaleSubnetRouteMark returns the TailscaleSubnetRouteMark in bytes.
func getTailscaleSubnetRouteMark() []byte {
	return []byte{0x08, 0x0c, 0x00, 0x00}
}

// checkIPv6ForTest can be set in tests.
var checkIPv6ForTest func(logger.Logf) error

// checkIPv6 checks whether the system appears to have a working IPv6
// network stack. It returns an error explaining what looks wrong or
// missing.  It does not check that IPv6 is currently functional or
// that there's a global address, just that the system would support
// IPv6 if it were on an IPv6 network.
func CheckIPv6(logf logger.Logf) error {
	if f := checkIPv6ForTest; f != nil {
		return f(logf)
	}

	_, err := os.Stat("/proc/sys/net/ipv6")
	if os.IsNotExist(err) {
		return err
	}
	bs, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if err != nil {
		// Be conservative if we can't find the IPv6 configuration knob.
		return err
	}
	disabled, err := strconv.ParseBool(strings.TrimSpace(string(bs)))
	if err != nil {
		return errors.New("disable_ipv6 has invalid bool")
	}
	if disabled {
		return errors.New("disable_ipv6 is set")
	}

	// Older kernels don't support IPv6 policy routing. Some kernels
	// support policy routing but don't have this knob, so absence of
	// the knob is not fatal.
	bs, err = os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_policy")
	if err == nil {
		disabled, err = strconv.ParseBool(strings.TrimSpace(string(bs)))
		if err != nil {
			return errors.New("disable_policy has invalid bool")
		}
		if disabled {
			return errors.New("disable_policy is set")
		}
	}

	if err := CheckIPRuleSupportsV6(logf); err != nil {
		return fmt.Errorf("kernel doesn't support IPv6 policy routing: %w", err)
	}

	return nil
}

func CheckIPRuleSupportsV6(logf logger.Logf) error {
	// First try just a read-only operation to ideally avoid
	// having to modify any state.
	if rules, err := netlink.RuleList(netlink.FAMILY_V6); err != nil {
		return fmt.Errorf("querying IPv6 policy routing rules: %w", err)
	} else {
		if len(rules) > 0 {
			logf("[v1] kernel supports IPv6 policy routing (found %d rules)", len(rules))
			return nil
		}
	}

	// Try to actually create & delete one as a test.
	rule := netlink.NewRule()
	rule.Priority = 1234
	rule.Mark = TailscaleBypassMarkNum
	rule.Table = 52
	rule.Family = netlink.FAMILY_V6
	// First delete the rule unconditionally, and don't check for
	// errors. This is just cleaning up anything that might be already
	// there.
	netlink.RuleDel(rule)
	// And clean up on exit.
	defer netlink.RuleDel(rule)
	return netlink.RuleAdd(rule)
}
