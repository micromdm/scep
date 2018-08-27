// Package csrverifier defines an interface for CSR verification.
package csrverifier

// Verify the raw decrypted CSR.
type CSRVerifier interface {
	Verify(transactionID string, data []byte) (bool, error)
}
