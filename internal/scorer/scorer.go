// Package scorer evaluates a hostname against a set of TLS / DNS checks
// and produces a 0-100 readiness score for short-lived certificates.
package scorer

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Check identifiers.
const (
	CheckHandshake     = "handshake_chain"
	CheckNotExpired    = "not_expired"
	CheckShortValidity = "validity_leq_90"
	CheckStrongKey     = "strong_key_hash"
	CheckSANHost       = "san_contains_host"
	CheckAIA           = "aia_caissuers"
	CheckOCSPCRL       = "ocsp_or_crl"
	CheckCAA           = "caa_present"
	CheckSCT           = "sct_in_cert"
	CheckACMESurface   = "http_port_80"
)

// Check is one scored finding.
type Check struct {
	ID     string `json:"id"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
	Weight int    `json:"weight"`
}

// Report is the full evaluation of a host.
type Report struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Score          int      `json:"score"`
	DaysRemaining  int      `json:"daysRemaining"`
	NotAfter       string   `json:"notAfter,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	ValidityDays   int      `json:"validityDays"`
	PolicyFail398  bool     `json:"policyFail398"`
	Checks         []Check  `json:"checks"`
	Errors         []string `json:"errors"`
}

// Weights for each check. Documented in the README.
var Weights = map[string]int{
	CheckHandshake:     20,
	CheckNotExpired:    15,
	CheckShortValidity: 10,
	CheckStrongKey:     15,
	CheckSANHost:       10,
	CheckAIA:           10,
	CheckOCSPCRL:       5,
	CheckCAA:           10,
	CheckSCT:           5,
	CheckACMESurface:   5,
}

// Options controls how a host is evaluated.
type Options struct {
	Port               int
	Timeout            time.Duration
	InsecureSkipVerify bool
	// CAALookup, HTTPProbe and Dialer are injectable for tests.
	CAALookup func(domain string) (bool, error)
	HTTPProbe func(host string, timeout time.Duration) bool
	Dialer    func(address string, cfg *tls.Config, timeout time.Duration) (*tls.ConnectionState, error)
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Port:      443,
		Timeout:   10 * time.Second,
		CAALookup: LookupCAA,
		HTTPProbe: ProbeHTTP,
		Dialer:    dialTLS,
	}
}

// dialTLS performs a TLS handshake and returns the resulting connection state.
func dialTLS(address string, cfg *tls.Config, timeout time.Duration) (*tls.ConnectionState, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", address, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return &state, nil
}

// ProbeHTTP performs a short HEAD/GET against port 80 /.well-known/acme-challenge/ping.
// Any response (including 404) or a connection means HTTP is reachable.
func ProbeHTTP(host string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := "http://" + host + "/.well-known/acme-challenge/ping"
	resp, err := client.Get(url)
	if err != nil {
		// Even a TCP error is usually fatal here; try a raw TCP dial fallback.
		conn, derr := net.DialTimeout("tcp", host+":80", timeout)
		if derr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	resp.Body.Close()
	return true
}

// Score evaluates a host with the given options.
func Score(host string, opts Options) *Report {
	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.CAALookup == nil {
		opts.CAALookup = LookupCAA
	}
	if opts.HTTPProbe == nil {
		opts.HTTPProbe = ProbeHTTP
	}
	if opts.Dialer == nil {
		opts.Dialer = dialTLS
	}

	r := &Report{
		Host:   host,
		Port:   opts.Port,
		Score:  100,
		Checks: []Check{},
		Errors: []string{},
	}

	address := net.JoinHostPort(host, strconv.Itoa(opts.Port))

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	state, err := opts.Dialer(address, cfg, opts.Timeout)
	if err != nil {
		r.Errors = append(r.Errors, "tls dial: "+err.Error())
		// Fail every check that depends on the handshake and return.
		for _, id := range []string{CheckHandshake, CheckNotExpired, CheckShortValidity,
			CheckStrongKey, CheckSANHost, CheckAIA, CheckOCSPCRL, CheckSCT} {
			r.addFail(id, "no handshake")
		}
		// CAA and HTTP can still be probed.
		r.evalCAA(host, opts)
		r.evalHTTP(host, opts)
		r.clampScore()
		return r
	}

	if len(state.PeerCertificates) == 0 {
		r.Errors = append(r.Errors, "no peer certificates presented")
		r.addFail(CheckHandshake, "no peer certs")
		r.clampScore()
		return r
	}

	leaf := state.PeerCertificates[0]
	r.Issuer = leaf.Issuer.CommonName
	r.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	r.DaysRemaining = int(time.Until(leaf.NotAfter).Hours() / 24)
	r.ValidityDays = int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
	r.PolicyFail398 = r.ValidityDays > 398

	// A. handshake + chain to system roots (handled by Dialer when InsecureSkipVerify=false).
	// We also try an explicit Verify using the presented intermediates for extra signal.
	if opts.InsecureSkipVerify {
		r.addFail(CheckHandshake, "insecure skip verify; chain not validated")
	} else {
		pool := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			pool.AddCert(c)
		}
		_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: pool})
		if verr != nil {
			r.addFail(CheckHandshake, "chain verify failed: "+verr.Error())
		} else {
			r.addPass(CheckHandshake, "chain verifies to system roots")
		}
	}

	// B. not expired / >14 days.
	if r.DaysRemaining < 0 {
		r.addFail(CheckNotExpired, fmt.Sprintf("expired %d days ago", -r.DaysRemaining))
	} else if r.DaysRemaining < 14 {
		r.addFail(CheckNotExpired, fmt.Sprintf("only %d days remaining", r.DaysRemaining))
	} else {
		r.addPass(CheckNotExpired, fmt.Sprintf("%d days remaining", r.DaysRemaining))
	}

	// C. short validity ≤ 90 days (path to 47).
	switch {
	case r.ValidityDays > 398:
		r.addFail(CheckShortValidity, fmt.Sprintf("validity %d days > 398 (policy fail)", r.ValidityDays))
	case r.ValidityDays > 90:
		r.addFail(CheckShortValidity, fmt.Sprintf("validity %d days > 90 (informational for 2029)", r.ValidityDays))
	default:
		r.addPass(CheckShortValidity, fmt.Sprintf("validity %d days ≤ 90", r.ValidityDays))
	}

	// D. strong key + hash.
	if ok, detail := evalStrongKey(leaf); ok {
		r.addPass(CheckStrongKey, detail)
	} else {
		r.addFail(CheckStrongKey, detail)
	}

	// E. SAN contains hostname.
	if leaf.VerifyHostname(host) == nil {
		r.addPass(CheckSANHost, "SAN includes "+host)
	} else {
		r.addFail(CheckSANHost, "SAN does not include "+host)
	}

	// F. AIA caIssuers present.
	if len(leaf.IssuingCertificateURL) > 0 {
		r.addPass(CheckAIA, strings.Join(leaf.IssuingCertificateURL, ","))
	} else {
		r.addFail(CheckAIA, "no AIA caIssuers URI on leaf")
	}

	// G. OCSP or CRL distribution points present.
	if len(leaf.OCSPServer) > 0 || len(leaf.CRLDistributionPoints) > 0 {
		detail := ""
		if len(leaf.OCSPServer) > 0 {
			detail = "ocsp=" + strings.Join(leaf.OCSPServer, ",")
		}
		if len(leaf.CRLDistributionPoints) > 0 {
			if detail != "" {
				detail += "; "
			}
			detail += "crl=" + strings.Join(leaf.CRLDistributionPoints, ",")
		}
		r.addPass(CheckOCSPCRL, detail)
	} else {
		r.addFail(CheckOCSPCRL, "no OCSP or CRL URIs on leaf")
	}

	// H. SCT in cert.
	if HasSCTExtension(leaf) {
		r.addPass(CheckSCT, "SCT extension present on leaf")
	} else {
		r.addFail(CheckSCT, "SCT not in cert (may be TLS stapled — not checked in v1)")
	}

	// I. CAA (DNS).
	r.evalCAA(host, opts)

	// J. HTTP :80 reachable.
	r.evalHTTP(host, opts)

	r.clampScore()
	return r
}

func (r *Report) evalCAA(host string, opts Options) {
	domain := effectiveDomain(host)
	ok, err := opts.CAALookup(domain)
	if err != nil {
		r.addFail(CheckCAA, "CAA lookup error: "+err.Error())
		return
	}
	if ok {
		r.addPass(CheckCAA, "CAA records present for "+domain)
	} else {
		r.addFail(CheckCAA, "no CAA records for "+domain)
	}
}

func (r *Report) evalHTTP(host string, opts Options) {
	if opts.HTTPProbe(host, opts.Timeout) {
		r.addPass(CheckACMESurface, "port 80 reachable (ACME surface)")
	} else {
		r.addFail(CheckACMESurface, "port 80 not reachable")
	}
}

func (r *Report) addPass(id, detail string) {
	r.Checks = append(r.Checks, Check{ID: id, Pass: true, Detail: detail, Weight: Weights[id]})
}

func (r *Report) addFail(id, detail string) {
	r.Checks = append(r.Checks, Check{ID: id, Pass: false, Detail: detail, Weight: Weights[id]})
	r.Score -= Weights[id]
}

func (r *Report) clampScore() {
	if r.Score < 0 {
		r.Score = 0
	}
	if r.Score > 100 {
		r.Score = 100
	}
}

// ErrNoCerts is returned when a peer presented no certificates.
var ErrNoCerts = errors.New("no peer certificates")

// effectiveDomain returns a reasonable parent for CAA lookup.
// For "www.example.com" → "example.com" using a naive registrable-domain heuristic.
// This is intentionally simple for v1 and will not handle multi-label TLDs.
func effectiveDomain(host string) string {
	host = strings.TrimSuffix(host, ".")
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
