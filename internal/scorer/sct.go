package scorer

import (
	"crypto/x509"
	"encoding/asn1"
)

// SCTListOID is the OID for the X.509v3 extension embedding SCTs (RFC 6962 §3.3).
var SCTListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// HasSCTExtension returns true if the cert embeds the RFC 6962 SCT list extension.
// We do not parse the SCT contents in v1 — presence of the extension is enough signal.
func HasSCTExtension(c *x509.Certificate) bool {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(SCTListOID) {
			return true
		}
	}
	return false
}
