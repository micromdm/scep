// Package certfailer defines an interface for cert failure notifications.
package certfailer

// Verify the raw decrypted CSR.
type CertFailer interface {
	Fail(transactionID string, data []byte, errmsg string) (bool, error)
}
