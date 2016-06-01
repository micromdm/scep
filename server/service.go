package scepserver

import "github.com/micromdm/scep/scep"

// Service is the interface for all supported SCEP server operations
type Service interface {
	// GetCACaps returns a list of options
	// which are supported by the server.
	GetCACaps() ([]byte, error)

	// GetCACert returns CA certificate or
	// a CA certificate chain with intermediates
	// in a PKCS#7 Degenerate Certificates format
	GetCACert() ([]byte, error)

	// PKIOperation handles incoming SCEP messages such as PKCSReq and
	// sends back a CertRep PKIMessag.
	PKIOperation(*scep.PKIMessage) (*scep.PKIMessage, error)

	// GetNextCACert returns a replacement certificate or certificate chain
	// when the old one expires. The response format is a PKCS#7 Degenerate
	// Certificates type.
	GetNextCACert() ([]byte, error)
}
