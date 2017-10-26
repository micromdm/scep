// Package csrverifier defines an interface for CSR verification
package csrverifier

// Verify the CSR Raw request
type CSRVerifier interface {
	Verify(data []byte) (bool, error)
}
