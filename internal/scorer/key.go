package scorer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// evalStrongKey returns (pass, detail). Fails on RSA<2048, SHA-1 signatures, or unknown algorithms.
func evalStrongKey(leaf *x509.Certificate) (bool, string) {
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		return false, "weak signature: " + leaf.SignatureAlgorithm.String()
	}
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return false, fmt.Sprintf("RSA %d < 2048", k.N.BitLen())
		}
		return true, fmt.Sprintf("RSA %d, %s", k.N.BitLen(), leaf.SignatureAlgorithm.String())
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return true, fmt.Sprintf("ECDSA %s, %s", k.Curve.Params().Name, leaf.SignatureAlgorithm.String())
		default:
			return false, "ECDSA with unsupported curve"
		}
	default:
		return false, "unknown public key algorithm"
	}
}
