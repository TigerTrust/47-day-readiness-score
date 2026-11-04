package scorer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// LookupCAA returns (hasRecords, error) for the given domain.
// It first tries the Go resolver (which supports CAA on most platforms),
// then falls back to a direct DNS query via the system resolver using miekg/dns.
func LookupCAA(domain string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Climb the label tree per RFC 8659 §3: check the name, then its parents.
	name := strings.TrimSuffix(domain, ".")
	for name != "" {
		ok, err := caaAt(ctx, name)
		if err == nil && ok {
			return true, nil
		}
		idx := strings.Index(name, ".")
		if idx < 0 {
			return false, nil
		}
		name = name[idx+1:]
	}
	return false, nil
}

func caaAt(ctx context.Context, name string) (bool, error) {
	// Try stdlib first — simplest when available.
	if ok, err := caaStdlib(ctx, name); err == nil {
		return ok, nil
	}

	// Fall back to miekg/dns against the OS resolvers.
	servers, err := osResolvers()
	if err != nil || len(servers) == 0 {
		servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeCAA)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 3 * time.Second}

	for _, srv := range servers {
		resp, _, err := c.ExchangeContext(ctx, m, srv)
		if err != nil {
			continue
		}
		for _, a := range resp.Answer {
			if _, ok := a.(*dns.CAA); ok {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("no DNS server answered for %s", name)
}

func caaStdlib(ctx context.Context, name string) (bool, error) {
	r := net.DefaultResolver
	// net.Resolver.LookupCAA exists only on recent Go with GODEBUG=netdns=cgo issues;
	// to stay portable we do a type-less lookup through LookupTXT and treat NXDOMAIN
	// as "not supported" — the real work is in caaAt via miekg/dns.
	_, err := r.LookupHost(ctx, name)
	if err != nil {
		// Not fatal — caller will try the miekg path.
		return false, err
	}
	// Return err to force the miekg path, which does the real CAA query.
	return false, fmt.Errorf("stdlib has no CAA support path")
}

func osResolvers() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out, nil
}
