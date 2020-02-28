package tunneldns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/forward"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type whitelistType map[string][]*dns.A

// DNS53Plugin is an adapter for CoreDNS and built-in metrics
type DNS53Plugin struct {
	Forwarder *forward.Forward

	L                sync.RWMutex
	AutoWhitelistURL string
	HTTPWhitelist    []string
	Whitelist        whitelistType

	Next plugin.Handler
}

func NewDNS53lugin(chain plugin.Handler, whitelist []string) *DNS53Plugin {
	fwSetupChains()

	p := &DNS53Plugin{
		Next:          chain,
		HTTPWhitelist: []string{},
		Whitelist:     make(whitelistType),
	}

	for _, entry := range whitelist {
		if strings.HasPrefix(entry, "auto:") {
			if p.AutoWhitelistURL != "" {
				logger.WithField("whitelist-entry", entry).Fatal("Found multiple auto: entries")
			}

			p.AutoWhitelistURL = entry[len("auto:"):]
			if p.AutoWhitelistURL == "" {
				concheckuri, err := getNMConnectivityCheckURL()
				if err != nil {
					logger.WithError(err).Fatal("Error retrieving connectivity check URL")
				}
				p.AutoWhitelistURL = concheckuri
			}

			url, err := url.Parse(p.AutoWhitelistURL)
			if err != nil {
				logger.WithField("url", p.AutoWhitelistURL).WithError(err).Fatal("Error parsing auto whitelist URL")
			}
			p.HTTPWhitelist = append(p.HTTPWhitelist, url.Hostname())

			logger.WithField("auto-whitelist-url", p.AutoWhitelistURL).Info("Configuring DNS53 fallback with auto whitelist")
			continue
		}

		if strings.HasPrefix(entry, "http:") {
			entry = entry[len("http:"):]

			url, err := url.Parse(entry)
			if err != nil {
				logger.WithField("url", entry).WithError(err).Fatal("Error parsing whitelisted HTTP URL")
			}
			p.HTTPWhitelist = append(p.HTTPWhitelist, url.Hostname())

			continue
		}

		if !strings.HasSuffix(entry, ".") {
			entry = entry + "."
		}
		// An empty list means we will resolve on request
		p.Whitelist[entry] = []*dns.A{}
	}

	logger.WithField("whitelist", whitelist).WithField("HTTPWhitelist", p.HTTPWhitelist).Info("Configuring whitelisted DNS53 fallback")

	// First, register for new updates
	go func() {
		nsch, cpch := watchDHCPNameserverChanges()
		for {
			select {
			case newns := <-nsch:
				p.updateNameservers(newns)
			case newcp := <-cpch:
				p.updateState(newcp)
			}
		}
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

	p.L.Lock()
	p.Whitelist = make(whitelistType)
	p.L.Unlock()

	if tmpfwd == nil {
		logger.Info("Cleared DNS53 whitelist")
		return
	}

	newWhitelist := make(whitelistType)

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

			logger.WithField("hostname", hostname).Debug("Looking up via DNS53 temporary forwarder")

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

			As := []*dns.A{}
			for _, ans := range resp.Answer {
				A, ok := ans.(*dns.A)
				if !ok {
					continue
				}
				fwAllowOutbound(A.A.String(), "tcp", "80")
				As = append(As, A)
			}
			if len(As) == 0 {
				logger.WithField("answer", resp.Answer).Error("Error getting outbound As")
			}
			newWhitelist[hostname+"."] = As

			respA := As[0]
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

	if len(newWhitelist) == 1 {
		logger.Info("Did not detect a captive portal, marking global connection")
		p.updateState(NM_STATE_CONNECTED_GLOBAL)
		return
	}

	p.L.Lock()
	p.Whitelist = newWhitelist
	p.L.Unlock()
	logger.WithField("whitelist", newWhitelist).Info("New DNS53 whitelist applied")
}

func (p *DNS53Plugin) allowHTTPWhitelist() {
	// Allow outbound URL on port 80 to HTTP whitelisted hosts
	for _, hostname := range p.HTTPWhitelist {
		ips, err := net.LookupIP(hostname)
		if err != nil {
			logger.WithError(err).Error("Error determining IPs for whitelist URL")
			return
		}
		for _, ip := range ips {
			if strings.Contains(ip.String(), ":") {
				// No IPv6
				continue
			}
			fwAllowOutbound(ip.String(), "tcp", "80")
		}
	}
}

func (p *DNS53Plugin) updateState(state nmstate) {
	p.L.Lock()
	defer p.L.Unlock()

	logger.WithField("state", state).Info("NetworkManager state changed")
	if state != NM_STATE_CONNECTED_GLOBAL {
		return
	}

	logger.Info("Global state detected, clearing whitelist and iptables allows")
	p.Whitelist = make(whitelistType)
	fwClearOutbounds()
	p.allowHTTPWhitelist()
}

func (p *DNS53Plugin) updateNameservers(nameservers []string) {
	logger.WithField("nameservers", nameservers).Info("Updating DNS53 nameservers")

	fwClearOutbounds()

	var newfwd *forward.Forward

	if len(nameservers) != 0 {
		newfwd = forward.New()
		for _, ns := range nameservers {
			fwAllowOutbound(ns, "udp", "53")

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
	p.L.Lock()
	defer p.L.Unlock()

	oldfwd := p.Forwarder
	p.Forwarder = newfwd
	if oldfwd != nil {
		oldfwd.Close()
	}
}

// ServeDNS implements the CoreDNS plugin interface
func (p DNS53Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	isWhitelisted := true
	var results []*dns.A
	if len(r.Question) > 1 {
		logger.WithField("questions", r.Question).Info("More than one question, not-whitelisted")
		isWhitelisted = false
	} else {
		results, isWhitelisted = p.Whitelist[r.Question[0].Name]
	}

	if !isWhitelisted {
		// At least one non-whitelisted question was asked, let's send all of it down the chain!
		return p.Next.ServeDNS(ctx, w, r)
	}

	p.L.RLock()
	defer p.L.RUnlock()

	remark := ""
	if len(results) != 0 {
		remark = " (cached)"
	}

	logger.WithField("question", r.Question).Infof("Whitelisted request, using%s DNS53", remark)
	if p.Forwarder == nil {
		logger.Info("No DNS53 forwarders configured, attempting DoH for whitelisted query")
		return p.Next.ServeDNS(ctx, w, r)
	}

	// All were whitelisted, which means it's a captive portal signin. Let's do DNS53
	if len(results) != 0 {
		rrres := make([]dns.RR, len(results))
		for i, res := range results {
			rrres[i] = res
		}

		// Return cached result from auto-whitelisting
		state := request.Request{W: w, Req: r}

		a := new(dns.Msg)
		a.SetReply(r)
		a.Authoritative = true
		a.Answer = rrres

		state.SizeAndDo(a)
		w.WriteMsg(a)

		return 0, nil
	} else {
		return p.Forwarder.ServeDNS(ctx, w, r)
	}
}

// Name implements the CoreDNS plugin interface
func (p DNS53Plugin) Name() string { return "dns53" }
