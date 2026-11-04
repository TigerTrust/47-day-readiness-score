package scorer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func mustGenECDSA(t *testing.T, days int) (*x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, der
}

func TestEvalStrongKey_ECDSA(t *testing.T) {
	c, _ := mustGenECDSA(t, 30)
	ok, detail := evalStrongKey(c)
	if !ok {
		t.Fatalf("expected pass, got %q", detail)
	}
}

func TestEvalStrongKey_WeakRSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	c, _ := x509.ParseCertificate(der)
	ok, detail := evalStrongKey(c)
	if ok {
		t.Fatalf("expected fail for 1024-bit RSA, got pass: %s", detail)
	}
}

func TestHasSCTExtension(t *testing.T) {
	c, _ := mustGenECDSA(t, 30)
	if HasSCTExtension(c) {
		t.Fatal("unexpected SCT on freshly generated cert")
	}
	c.Extensions = append(c.Extensions, pkix.Extension{Id: SCTListOID})
	if !HasSCTExtension(c) {
		t.Fatal("expected SCT extension to be detected")
	}
	// Sanity check: the OID constant parses to the RFC 6962 value.
	want := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	if !SCTListOID.Equal(want) {
		t.Fatalf("SCTListOID = %v, want %v", SCTListOID, want)
	}
}

func TestEffectiveDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":        "example.com",
		"www.example.com":    "example.com",
		"api.www.example.com":"example.com",
		"localhost":          "localhost",
		"example.com.":       "example.com",
	}
	for in, want := range cases {
		if got := effectiveDomain(in); got != want {
			t.Errorf("effectiveDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScore_ShortValidityPass(t *testing.T) {
	cert, _ := mustGenECDSA(t, 60) // 60-day validity > 47 but ≤ 90, so passes ShortValidity
	opts := Options{
		Port:    443,
		Timeout: time.Second,
		CAALookup: func(string) (bool, error) { return true, nil },
		HTTPProbe: func(string, time.Duration) bool { return true },
		Dialer: func(_ string, _ *tls.Config, _ time.Duration) (*tls.ConnectionState, error) {
			return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, nil
		},
		InsecureSkipVerify: true, // skip chain verify in test
	}
	r := Score("example.com", opts)
	for _, c := range r.Checks {
		if c.ID == CheckShortValidity && !c.Pass {
			t.Fatalf("expected short-validity pass; got %q", c.Detail)
		}
	}
}

func TestScore_ValidityOver398Fails(t *testing.T) {
	cert, _ := mustGenECDSA(t, 500)
	opts := Options{
		Port: 443, Timeout: time.Second,
		CAALookup: func(string) (bool, error) { return false, nil },
		HTTPProbe: func(string, time.Duration) bool { return false },
		Dialer: func(_ string, _ *tls.Config, _ time.Duration) (*tls.ConnectionState, error) {
			return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, nil
		},
		InsecureSkipVerify: true,
	}
	r := Score("example.com", opts)
	if !r.PolicyFail398 {
		t.Fatal("expected PolicyFail398=true for 500-day validity")
	}
	var found bool
	for _, c := range r.Checks {
		if c.ID == CheckShortValidity {
			found = true
			if c.Pass {
				t.Fatalf("expected ShortValidity to fail for 500-day cert")
			}
		}
	}
	if !found {
		t.Fatal("ShortValidity check not emitted")
	}
}

func TestScore_DialFailureStillProbesCAA(t *testing.T) {
	called := false
	opts := Options{
		Port: 443, Timeout: time.Second,
		CAALookup: func(string) (bool, error) { called = true; return true, nil },
		HTTPProbe: func(string, time.Duration) bool { return false },
		Dialer: func(_ string, _ *tls.Config, _ time.Duration) (*tls.ConnectionState, error) {
			return nil, errFake
		},
	}
	r := Score("example.com", opts)
	if !called {
		t.Fatal("expected CAA lookup even when dial fails")
	}
	if r.Score == 100 {
		t.Fatal("expected score penalties on dial failure")
	}
}

type fakeErr string

func (f fakeErr) Error() string { return string(f) }

var errFake = fakeErr("fake dial error")
