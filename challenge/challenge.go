// Package challenge defines an interface for a dynamic challenge password cache.
package challenge

import (
	"crypto/x509"
	"errors"

	"github.com/micromdm/scep/scep"
	scepserver "github.com/micromdm/scep/server"
)

// Store is a dynamic challenge password cache.
type Store interface {
	SCEPChallenge() (string, error)
	HasChallenge(pw string) (bool, error)
}

func csrSignerMiddleWare(store Store, next scepserver.CSRSigner) scepserver.CSRSignerFunc {
	return func(m *scep.CSRReqMessage) (*x509.Certificate, error) {
		// TODO: this was only verified in the old version if our MessageType was PKCSReq
		valid, err := store.HasChallenge(m.ChallengePassword)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, errors.New("invalid SCEP challenge")
		}
		return next.SignCSR(m)
	}
}

// NewCSRSignerMiddleware creates a new middleware adaptor
func NewCSRSignerMiddleware(store Store) func(scepserver.CSRSigner) scepserver.CSRSigner {
	return func(f scepserver.CSRSigner) scepserver.CSRSigner {
		return csrSignerMiddleWare(store, f)
	}
}
