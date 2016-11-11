package bolt

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"

	"github.com/boltdb/bolt"
)

// Depot implements a SCEP certifiacte store using boltdb.
// https://github.com/boltdb/bolt
type Depot struct {
	*bolt.DB
}

// NewBoltDepot creates a depot.Depot backed by BoltDB.
func NewBoltDepot(db *bolt.DB) *Depot {
	return &Depot{db}
}
func (db *Depot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	panic("not implemented")
}

func (db *Depot) Put(name string, crt *x509.Certificate) error {
	panic("not implemented")
}

func (db *Depot) Serial() (*big.Int, error) {
	panic("not implemented")
}

func (db *Depot) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) error {
	panic("not implemented")
}
