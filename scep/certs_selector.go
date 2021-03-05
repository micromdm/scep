package scep

import "crypto/x509"

// A CertsSelector filters certificates.
type CertsSelector interface {
	SelectCerts([]*x509.Certificate) []*x509.Certificate
}

// NopCertsSelector is a CertsSelector that does not do anything.
type NopCertsSelector struct{}

func (s NopCertsSelector) SelectCerts(certs []*x509.Certificate) []*x509.Certificate {
	return certs
}

// A EnciphermentCertsSelector is a CertsSelector that selects
// certificates eligible for key encipherment. This selector can be used
// to filter PKCSReq recipients.
type EnciphermentCertsSelector struct{}

func (s EnciphermentCertsSelector) SelectCerts(certs []*x509.Certificate) (selected []*x509.Certificate) {
	enciphermentKeyUsages := x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	for _, cert := range certs {
		if cert.KeyUsage&enciphermentKeyUsages != 0 {
			selected = append(selected, cert)
		}
	}
	return selected
}
