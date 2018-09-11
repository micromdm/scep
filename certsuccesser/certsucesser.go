// Package certsuccesser defines an interface for cert success notifications.
package certsuccesser

// Verify the raw decrypted CSR.
type CertSuccesser interface {
	Success(transactionID string, data []byte, certFilename string) (bool, error)
}
