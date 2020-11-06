// Package csrverifier defines an interface for CSR verification.
package csrverifier

import "context"

// Verify the raw decrypted CSR.
type CSRVerifier interface {
	Verify(data []byte) (bool, error)
}

// Verify the CSR and Challenge together
type CombinedVerifier interface {
	Verify(ctx context.Context, data []byte, challenge string) (bool, error)
}
