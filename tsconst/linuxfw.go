// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconst

// Linux firewall constants used by Tailscale.

// The following bits are added to packet marks for Tailscale use.
//
// We tried to pick bits sufficiently out of the way that it's
// unlikely to collide with existing uses. We have 4 bytes of mark
// bits to play with. We leave the lower byte alone on the assumption
// that sysadmins would use those. Kubernetes uses a few bits in the
// second byte, so we steer clear of that too.
//
// Empirically, most of the documentation on packet marks on the
// internet gives the impression that the marks are 16 bits
// wide. Based on this, we theorize that the upper two bytes are
// relatively unused in the wild, and so we consume bits 16:23 (the
// third byte).
//
// The constants are in the iptables/iproute2 string format for
// matching and setting the bits, so they can be directly embedded in
// commands.

// NOTICE: The marks for generic Linux are modified for Android!
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
// In addition to that, we also claim the protectedFromVpn bit to avoid going through system VPN
const (
	// The mask for reading/writing the 'firewall mask' bits on a packet.
	// See the comment on the const block on why we only use the third byte.
	//
	// We claim bits 16:23 entirely. For now we only use the lower four
	// bits, leaving the higher 4 bits for future use.
	LinuxFwmarkMask    = "0x1e020000"
	LinuxFwmarkMaskNum = 0x1e020000

	// Packet is from Tailscale and to a subnet route destination, so
	// is allowed to be routed through this machine.
	LinuxSubnetRouteMark    = "0x8000000"
	LinuxSubnetRouteMarkNum = 0x8000000

	// Packet was originated by tailscaled itself, and must not be
	// routed over the Tailscale network.
	LinuxBypassMark    = "0x10020000"
	LinuxBypassMarkNum = 0x10020000
)
