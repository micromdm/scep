package scep

import (
	"crypto/sha256"
	"crypto/x509"
)

// A CertsSelector filters certificates.
type CertsSelector interface {
	SelectCerts([]*x509.Certificate) []*x509.Certificate
}

// CertsSelectorFunc is a type of function that filters certificates.
type CertsSelectorFunc func([]*x509.Certificate) []*x509.Certificate

func (f CertsSelectorFunc) SelectCerts(certs []*x509.Certificate) []*x509.Certificate {
	return f(certs)
}

// NopCertsSelector returns a CertsSelectorFunc that does not do anything.
func NopCertsSelector() CertsSelectorFunc {
	return func(certs []*x509.Certificate) []*x509.Certificate {
		return certs
	}
}

// A EnciphermentCertsSelector returns a CertsSelectorFunc that selects
// certificates eligible for key encipherment. This certsSelector can be used
// to filter PKCSReq recipients.
func EnciphermentCertsSelector() CertsSelectorFunc {
	return func(certs []*x509.Certificate) (selected []*x509.Certificate) {
		enciphermentKeyUsages := x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
		for _, cert := range certs {
			if cert.KeyUsage&enciphermentKeyUsages != 0 {
				selected = append(selected, cert)
			}
		}
		return selected
	}
}

// SHA256FingerprintCertsSelector selects a certificate that matches
// a SHA-256 hash of the raw certificate DER bytes
func SHA256FingerprintCertsSelector(hash [32]byte) CertsSelectorFunc {
	return func(certs []*x509.Certificate) (selected []*x509.Certificate) {
		for _, cert := range certs {
			if sha256.Sum256(cert.Raw) == hash {
				selected = append(selected, cert)
				return
			}
		}
		return
	}
}
