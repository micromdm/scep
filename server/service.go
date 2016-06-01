package scepserver

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/micromdm/scep/scep"

	"golang.org/x/net/context"
)

// Service is the interface for all supported SCEP server operations.
type Service interface {
	// GetCACaps returns a list of options
	// which are supported by the server.
	GetCACaps(ctx context.Context) ([]byte, error)

	// GetCACert returns CA certificate or
	// a CA certificate chain with intermediates
	// in a PKCS#7 Degenerate Certificates format
	GetCACert(ctx context.Context) ([]byte, error)

	// PKIOperation handles incoming SCEP messages such as PKCSReq and
	// sends back a CertRep PKIMessag.
	PKIOperation(ctx context.Context, msg []byte) ([]byte, error)

	// GetNextCACert returns a replacement certificate or certificate chain
	// when the old one expires. The response format is a PKCS#7 Degenerate
	// Certificates type.
	GetNextCACert(ctx context.Context) ([]byte, error)
}

type service struct {
	depot       Depot
	ca          []*x509.Certificate // CA cert or chain
	caKey       *rsa.PrivateKey
	csrTemplate *x509.Certificate
}

func (svc service) GetCACaps(ctx context.Context) ([]byte, error) {
	defaultCaps := []byte(`POSTPKIOperation`)
	return defaultCaps, nil
}

func (svc service) GetCACert(ctx context.Context) ([]byte, error) {
	if len(svc.ca) == 0 {
		return nil, errors.New("missing CA Cert")
	}
	return scep.DegenerateCertificates(svc.ca)
}

func (svc service) PKIOperation(ctx context.Context, data []byte) ([]byte, error) {
	msg, err := scep.ParsePKIMessage(data)
	if err != nil {
		// handle err
		return nil, err
	}
	ca := svc.ca[0]
	if err := msg.DecryptPKIEnvelope(svc.ca[0], svc.caKey); err != nil {
		return nil, err
	}

	csr := msg.CSRReqMessage.CSR
	id, err := generateSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	// create cert template
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-600).UTC(),
		NotAfter:     time.Now().AddDate(1, 0, 0).UTC(),
		SubjectKeyId: id,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
			x509.ExtKeyUsageClientAuth,
		},
	}

	certRep, err := msg.SignCSR(ca, svc.caKey, tmpl)
	if err != nil {
		return nil, err
	}

	return certRep.Raw, nil

}

func (svc service) GetNextCACert(ctx context.Context) ([]byte, error) {
	panic("not implemented")
}

// NewService creates a new scep service
func NewService(depot Depot, password []byte) (Service, error) {
	ca, caKey, err := depot.CA(password)
	if err != nil {
		return nil, err
	}
	return &service{
		depot: depot,
		ca:    ca,
		caKey: caKey,
	}, nil
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
