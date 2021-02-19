package depot

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	scepserver "github.com/micromdm/scep/server"

	"github.com/micromdm/scep/scep"
)

// CSRSigner returns a CSRSignerFunc for use in new scepserver service
func CSRSigner(depot Depot, allowRenewal, clientValidity int, caPass string) scepserver.CSRSignerFunc {
	return func(m *scep.CSRReqMessage) (*x509.Certificate, error) {
		csr := m.CSR
		id, err := generateSubjectKeyID(csr.PublicKey)
		if err != nil {
			return nil, err
		}

		serial, err := depot.Serial()
		if err != nil {
			return nil, err
		}

		// create cert template
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			NotBefore:    time.Now().Add(-600).UTC(),
			NotAfter:     time.Now().AddDate(0, 0, clientValidity).UTC(),
			SubjectKeyId: id,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			SignatureAlgorithm: csr.SignatureAlgorithm,
			DNSNames:           csr.DNSNames,
			EmailAddresses:     csr.EmailAddresses,
			IPAddresses:        csr.IPAddresses,
			URIs:               csr.URIs,
		}

		crts, key, err := depot.CA([]byte(caPass))
		ca := crts[0]
		// sign the CSR creating a DER encoded cert
		crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca, m.CSR.PublicKey, key)
		if err != nil {
			return nil, err
		}
		// parse the certificate
		crt, err := x509.ParseCertificate(crtBytes)
		if err != nil {
			return nil, err
		}

		name := certName(crt)

		// Test if this certificate is already in the CADB, revoke if needed
		// revocation is done if the validity of the existing certificate is
		// less than allowRenewal (14 days by default)
		_, err = depot.HasCN(name, allowRenewal, crt, false)
		if err != nil {
			return nil, err
		}

		if err := depot.Put(name, crt); err != nil {
			return nil, err
		}

		return crt, nil
	}
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return string(crt.Signature)
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// ID is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
