// Package validator defines an interface for CSR validation
package validator

// Verify the CSR Raw request
type Validator interface {
	Verify(data []byte) (bool, error)
}
