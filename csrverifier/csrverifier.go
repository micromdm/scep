// Package csrverifier defines an interface for CSR verification.
package csrverifier

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/micromdm/scep/v2/scep"
	scepserver "github.com/micromdm/scep/v2/server"
)

// CSRVerifier verifies the raw decrypted CSR.
type CSRVerifier interface {
	Verify(data []byte) (bool, error)
}

// Middleware wraps next in a CSRSigner that runs verifier
func Middleware(verifier CSRVerifier, next scepserver.CSRSignerContext) scepserver.CSRSignerContextFunc {
	return func(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
		ok, err := verifier.Verify(m.RawDecrypted)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("CSR verify failed")
		}
		return next.SignCSRContext(ctx, m)
	}
}
