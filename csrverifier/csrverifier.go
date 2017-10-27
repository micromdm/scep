// Package csrverifier defines an interface for CSR verification.
package csrverifier

// Verify the raw decrypted CSR.
type CSRVerifier interface {
	Verify(data []byte) (bool, error)
}
