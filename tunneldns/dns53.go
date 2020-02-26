package tunneldns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/forward"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// DNS53Plugin is an adapter for CoreDNS and built-in metrics
type DNS53Plugin struct {
	Forwarder *forward.Forward

	AutoWhitelistURL string
	Whitelist        map[string]string

	Next plugin.Handler
}

func NewDNS53lugin(chain plugin.Handler, whitelist []string) *DNS53Plugin {

	p := &DNS53Plugin{
		Next:      chain,
		Whitelist: make(map[string]string),
	}

	if len(whitelist) == 1 && strings.HasPrefix(whitelist[0], "auto:") {
		p.AutoWhitelistURL = whitelist[0][len("auto:"):]

		logger.WithField("auto-whitelist-url", p.AutoWhitelistURL).Info("Configuring DNS53 fallback with auto whitelist")
	} else {
		for _, entry := range whitelist {
			if strings.HasPrefix(entry, "auto:") {
				logger.WithField("whitelist-entry", entry).Fatal("Determined auto: with multiple entries")
			}
			if !strings.HasSuffix(entry, ".") {
				entry = entry + "."
			}
			p.Whitelist[entry] = entry
		}

		logger.WithField("whitelist", whitelist).Info("Configuring whitelisted DNS53 fallback")
	}

	// First, register for new updates
	go func() {
		nsch := watchDHCPNameserverChanges()
		for newns := range nsch {
			p.updateNameservers(newns)
		}
		panic("For some reason, NM watching ended")
	}()

	// Then, make sure we catch up on the existing values
	dns, err := getDHCPNameServers()
	if err != nil {
		panic(err)
	}
	p.updateNameservers(dns)

	return p
}

func (p *DNS53Plugin) determineAutoWhitelist(tmpfwd *forward.Forward) {
	// Perform a request to the autowhitelist address to determine which domains are
	// used to log in to the captive portal.

	if p.AutoWhitelistURL == "" {
		logger.Debug("Not updating auto-whitelist")
		return
	}

	p.Whitelist = make(map[string]string)

	if tmpfwd == nil {
		logger.Info("Cleared DNS53 whitelist")
		return
	}

	newWhitelist := []string{}

	logger.WithField("url", p.AutoWhitelistURL).Info("Determining DNS53 whitelist")

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: false,
	}

	lookupDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network == "tcp" {
			addrparts := strings.Split(addr, ":")
			hostname := addrparts[0]

			newWhitelist = append(newWhitelist, hostname+".")

			logger.WithField("hostname", hostname).Debug("Looking up via DNS53 temporary forwarder")

			// TODO: Use tmpfwd to lookup
			m := new(dns.Msg)
			m.SetQuestion(hostname+".", dns.TypeA)
			rw := &test.ResponseWriter{}
			r := request.Request{
				Context: ctx,
				Req:     m,
				W:       rw,
			}

			resp, err := tmpfwd.Forward(r)
			if err != nil {
				logger.WithError(err).Error("Unable to resolve via DNS53 forward")
				return nil, fmt.Errorf("Unable to resolve %s via DNS53 forward: %s", hostname, err)
			}
			if len(resp.Answer) == 0 {
				return nil, fmt.Errorf("Unable to resolve %s via DNS53 forward: no results", hostname)
			}
			respA := resp.Answer[0].(*dns.A)
			logger.WithField("hostname", hostname).WithField("IPaddr", respA.A.String()).Debug("Resolved host")
			ip := respA.A.String()

			// Reconstruct host:port
			addr = ip + ":" + addrparts[1]
		}

		return dialer.DialContext(ctx, network, addr)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           lookupDialer,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	_, err := client.Get(p.AutoWhitelistURL)
	if err != nil {
		logger.WithError(err).Error("Error determining new DNS53 whitelist")
		return
	}

	for _, entry := range newWhitelist {
		p.Whitelist[entry] = entry
	}
	logger.WithField("whitelist", newWhitelist).Info("New DNS53 whitelist applied")
}

func (p *DNS53Plugin) updateNameservers(nameservers []string) {
	logger.WithField("nameservers", nameservers).Info("Updating DNS53 nameservers")

	var newfwd *forward.Forward

	if len(nameservers) != 0 {
		newfwd = forward.New()
		for _, ns := range nameservers {
			proxy := forward.NewProxy(ns+":53", transport.DNS)
			newfwd.SetProxy(proxy)
		}
		err := newfwd.OnStartup()
		if err != nil {
			logger.WithError(err).Error("Error starting new DNS53 forwarder")
			newfwd = nil
		}
	}
	p.determineAutoWhitelist(newfwd)

	// Now set up the new forwarder
	oldfwd := p.Forwarder
	p.Forwarder = newfwd
	if oldfwd != nil {
		oldfwd.Close()
	}
}

// ServeDNS implements the CoreDNS plugin interface
func (p DNS53Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	areAllWhitelisted := true
	for _, question := range r.Question {
		entry, isWhitelisted := p.Whitelist[question.Name]
		if !isWhitelisted || entry != question.Name {
			areAllWhitelisted = false
			break
		}
	}

	if !areAllWhitelisted {
		// At least one non-whitelisted question was asked, let's send all of it down the chain!
		return p.Next.ServeDNS(ctx, w, r)
	}

	logger.WithField("question", r.Question).Info("Whitelisted request, using DNS53")
	if p.Forwarder == nil {
		logger.Info("No DNS53 forwarders configured, attempting DoH for whitelisted query")
		return p.Next.ServeDNS(ctx, w, r)
	}

	// All were whitelisted, which means it's a captive portal signin. Let's do DNS53
	return p.Forwarder.ServeDNS(ctx, w, r)
}

// Name implements the CoreDNS plugin interface
func (p DNS53Plugin) Name() string { return "dns53" }
