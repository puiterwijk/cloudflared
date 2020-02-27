package tunneldns

import (
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	nmDest = "org.freedesktop.NetworkManager"
	nmPath = "/org/freedesktop/NetworkManager"

	dbusPropInterface     = "org.freedesktop.DBus.Properties"
	dbusPropChangedSignal = "PropertiesChanged"
)

func getDHCPNameServersFromActiveConnection(aconn dbus.ObjectPath) ([]string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("Error connecting to sysbus: %s", err)
	}

	conobj := conn.Object(nmDest, aconn)
	dhcp4confaddr, err := conobj.GetProperty("org.freedesktop.NetworkManager.Connection.Active.Dhcp4Config")
	if err != nil {
		return nil, fmt.Errorf("Error getting dhcp4confaddr: %s", err)
	}
	dhcp4conf := conn.Object(nmDest, dhcp4confaddr.Value().(dbus.ObjectPath))
	dhcp4optsvar, err := dhcp4conf.GetProperty("org.freedesktop.NetworkManager.DHCP4Config.Options")
	if err != nil {
		return nil, fmt.Errorf("Error getting dhcp4 options: %s", err)
	}
	dhcp4opts := dhcp4optsvar.Value().(map[string]dbus.Variant)
	dnsvar, hasdns := dhcp4opts["domain_name_servers"]
	if !hasdns {
		// No nameservers configured, nothing to see here
		return []string{}, nil
	}

	dns := dnsvar.Value().(string)

	return strings.Split(dns, " "), nil
}

func getNMConnectivityCheckURL() (string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", fmt.Errorf("Error connecting to sysbus: %s", err)
	}

	nmobj := conn.Object(nmDest, nmPath)
	urivar, err := nmobj.GetProperty(nmDest + ".ConnectivityCheckUri")
	if err != nil {
		return "", fmt.Errorf("Error getting connectivity check URL: %s", err)
	}
	return urivar.Value().(string), nil
}

func getDHCPNameServers() ([]string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("Error connecting to sysbus: %s", err)
	}

	nmobj := conn.Object(nmDest, nmPath)
	primconvar, err := nmobj.GetProperty(nmDest + ".PrimaryConnection")
	if err != nil {
		return nil, fmt.Errorf("Error getting primary conn: %s", err)
	}
	primcon := primconvar.Value().(dbus.ObjectPath)

	if primcon == "/" {
		return []string{}, nil
	}

	dns, err := getDHCPNameServersFromActiveConnection(primcon)
	if err != nil {
		return nil, fmt.Errorf("Error getting dns servers: %s", err)
	}
	return dns, nil
}

type nmstate uint32

const (
	NM_STATE_UNKNOWN          nmstate = 0
	NM_STATE_ASLEEP           nmstate = 10
	NM_STATE_DISCONNECTED     nmstate = 20
	NM_STATE_DISCONNECTING    nmstate = 30
	NM_STATE_CONNECTING       nmstate = 40
	NM_STATE_CONNECTED_LOCAL  nmstate = 50
	NM_STATE_CONNECTED_SITE   nmstate = 60
	NM_STATE_CONNECTED_GLOBAL nmstate = 70
)

func watchDHCPNameserverChanges() (<-chan []string, chan nmstate) {
	conn, err := dbus.SystemBus()
	if err != nil {
		panic(err)
	}

	err = conn.AddMatchSignal(
		dbus.WithMatchObjectPath(nmPath),
		dbus.WithMatchInterface(dbusPropInterface),
		dbus.WithMatchMember(dbusPropChangedSignal),
	)
	if err != nil {
		panic(err)
	}

	sigch := make(chan *dbus.Signal, 10)

	nschangech := make(chan []string, 5)
	cpchangech := make(chan nmstate)

	handlePCChange := func(primconvar dbus.Variant) {
		primconaddr := primconvar.Value().(dbus.ObjectPath)

		if primconaddr == "/" {
			// Got disconnected, no more nameservers valid
			logger.Info("Lost primaryconnection, clearing DNS53 forwarders")
			nschangech <- []string{}
			return
		}

		newns, err := getDHCPNameServersFromActiveConnection(primconaddr)
		if err != nil {
			logger.WithError(err).Error("Error getting DNS53 forwarders")
			nschangech <- []string{}
			return
		}
		logger.WithField("nameservers", newns).Info("Received new DNS53 forwarders")
		nschangech <- newns
	}

	handleStateChange := func(statevar dbus.Variant) {
		newstate := statevar.Value().(uint32)
		cpchangech <- nmstate(newstate)
	}

	go func() {
		conn.Signal(sigch)

		for v := range sigch {
			newprops := v.Body[1].(map[string]dbus.Variant)
			primconvar, pcchanged := newprops["PrimaryConnection"]
			if pcchanged {
				handlePCChange(primconvar)
			}
			statevar, statechanged := newprops["State"]
			if statechanged {
				handleStateChange(statevar)
			}
		}
	}()

	return nschangech, cpchangech
}
