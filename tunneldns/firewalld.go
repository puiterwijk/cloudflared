package tunneldns

import (
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	fwObjectPath      = "/org/fedoraproject/FirewallD1"
	fwInterface       = "org.fedoraproject.FirewallD1"
	fwInterfaceDirect = fwInterface + ".direct"

	fwIpS   = "ipv4"
	fwIpS6  = "ipv6"
	fwTable = "filter"

	fwChainDirect        = "OUTPUT_direct"
	fwChainCaptivePortal = "OUTPUT_captiveportal"
	fwChainBlock         = "OUTPUT_block_plaintext"
)

func getFWConn() dbus.BusObject {
	conn, err := dbus.SystemBus()
	if err != nil {
		panic(err)
	}
	return conn.Object(fwInterface, fwObjectPath)
}

func fwErrIsNotEnabledErr(err error) bool {
	return strings.HasPrefix(err.Error(), "NOT_ENABLED:")
}

func fwErrIsAlreadyEnabled(err error) bool {
	return strings.HasPrefix(err.Error(), "ALREADY_ENABLED:")
}

func fwSetupChains() {
	var res *dbus.Call
	conn := getFWConn()

	// Remove OUTPUT_direct calls to block/captivePortal chains if they exist
	res = conn.Call(fwInterfaceDirect+".removeRule", 0, fwIpS, fwTable, fwChainDirect, 1, []string{"-j", fwChainCaptivePortal})
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error removing forward to captivePortal chain")
	}
	res = conn.Call(fwInterfaceDirect+".removeRule", 0, fwIpS, fwTable, fwChainDirect, 2, []string{"-j", fwChainBlock})
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error removing forward to block chain")
	}

	// Remove the block and captivePortal chains if they exist
	res = conn.Call(fwInterfaceDirect+".removeRules", 0, fwIpS, fwTable, fwChainCaptivePortal)
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error clearing allow rules")
	}
	res = conn.Call(fwInterfaceDirect+".removeRules", 0, fwIpS, fwTable, fwChainBlock)
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error clearing allow rules")
	}
	res = conn.Call(fwInterfaceDirect+".removeChain", 0, fwIpS, fwTable, fwChainBlock)
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error removing block chain")
	}
	res = conn.Call(fwInterfaceDirect+".removeChain", 0, fwIpS, fwTable, fwChainCaptivePortal)
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error removing captivePortal chain")
	}

	// Create the block/captivePortal chains
	res = conn.Call(fwInterfaceDirect+".addChain", 0, fwIpS, fwTable, fwChainBlock)
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating block chain")
	}
	res = conn.Call(fwInterfaceDirect+".addChain", 0, fwIpS, fwTable, fwChainCaptivePortal)
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating captivePortal chain")
	}

	// Link to the block/captivePortal chains
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS, fwTable, fwChainDirect, 1, []string{"-j", fwChainCaptivePortal})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating forward to captivePortal chain")
	}
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS, fwTable, fwChainDirect, 2, []string{"-j", fwChainBlock})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating forward to block chain")
	}

	// Remove ip6tables plaintext block rules if they existed
	res = conn.Call(fwInterfaceDirect+".removeRule", 0, fwIpS6, fwTable, fwChainDirect, 1, []string{"-p", "udp", "--dport", "53", "-j", "REJECT"})
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error creating 53/UDP ipv6 block rule")
	}
	res = conn.Call(fwInterfaceDirect+".removeRule", 0, fwIpS6, fwTable, fwChainDirect, 2, []string{"-p", "tcp", "--dport", "53", "-j", "REJECT"})
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error creating 53/TCP ipv6 block rule")
	}
	res = conn.Call(fwInterfaceDirect+".removeRule", 0, fwIpS6, fwTable, fwChainDirect, 3, []string{"-p", "tcp", "--dport", "80", "-j", "REJECT"})
	if res.Err != nil && !fwErrIsNotEnabledErr(res.Err) {
		logger.WithError(res.Err).Fatal("Error creating 80/TCP ipv6 block rule")
	}

	// Block output ipv6 plaintext ports (assumption: captive portals won't use IPv6-only for captive portal signon)
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS6, fwTable, fwChainDirect, 1, []string{"-p", "udp", "--dport", "53", "-j", "REJECT"})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating 53/UDP ipv6 block rule")
	}
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS6, fwTable, fwChainDirect, 2, []string{"-p", "tcp", "--dport", "53", "-j", "REJECT"})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating 53/TCP ipv6 block rule")
	}
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS6, fwTable, fwChainDirect, 3, []string{"-p", "tcp", "--dport", "80", "-j", "REJECT"})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating 80/TCP ipv6 block rule")
	}

	// Add general ipv4 block chain rules
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS, fwTable, fwChainBlock, 1, []string{"-p", "udp", "--dport", "53", "-j", "REJECT"})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating 53/UDP ipv4 block rule")
	}
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS, fwTable, fwChainBlock, 2, []string{"-p", "tcp", "--dport", "53", "-j", "REJECT"})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating 53/TCP ipv4 block rule")
	}
	res = conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS, fwTable, fwChainBlock, 3, []string{"-p", "tcp", "--dport", "80", "-j", "REJECT"})
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error creating 80/TCP ipv4 block rule")
	}
}

func fwAllowOutbound(targetIP, proto, port string) {
	conn := getFWConn()

	res := conn.Call(fwInterfaceDirect+".addRule", 0, fwIpS, fwTable, fwChainCaptivePortal, 0, []string{"-p", proto, "--dport", port, "--dst", targetIP, "-j", "ACCEPT"})
	if res.Err != nil && !fwErrIsAlreadyEnabled(res.Err) {
		logger.WithError(res.Err).Fatal("Error creating allow rule")
	}
}

func fwClearOutbounds() {
	conn := getFWConn()

	res := conn.Call(fwInterfaceDirect+".removeRules", 0, fwIpS, fwTable, fwChainCaptivePortal)
	if res.Err != nil {
		logger.WithError(res.Err).Fatal("Error clearing allow rules")
	}
}
