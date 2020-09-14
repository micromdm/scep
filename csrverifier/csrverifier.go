// Package csrverifier defines an interface for CSR verification.
package csrverifier

import (
	"crypto/x509"
	"errors"

	"github.com/micromdm/scep/scep"
	scepserver "github.com/micromdm/scep/server"
)

// CSRVerifier verifies the raw decrypted CSR.
type CSRVerifier interface {
	Verify(data []byte) (bool, error)
}

func csrSignerMiddleWare(verifier CSRVerifier, next scepserver.CSRSignerFunc) scepserver.CSRSignerFunc {
	return func(m *scep.CSRReqMessage) (*x509.Certificate, error) {
		result, err := verifier.Verify(m.RawDecrypted)
		if err != nil {
			return nil, err
		}
		if !result {
			return nil, errors.New("CSR failed verification")
		}
		return next.SignCSR(m)
	}
}

// NewCSRSignerMiddleware creates a new middleware adaptor
func NewCSRSignerMiddleware(verifier CSRVerifier) func(scepserver.CSRSignerFunc) scepserver.CSRSignerFunc {
	return func(f scepserver.CSRSignerFunc) scepserver.CSRSignerFunc {
		return csrSignerMiddleWare(verifier, f)
	}
}
