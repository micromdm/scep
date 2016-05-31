package scep_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/micromdm/scep/scep"
)

func TestParsePKIMessage(t *testing.T) {
	pkcsReq := loadTestFile(t, "testdata/PKCSReq.der")
	msg, err := scep.ParsePKIMessage(pkcsReq)
	if err != nil {
		t.Fatal(err)
	}
	if msg.TransactionID == "" {
		t.Errorf("expected TransactionID attribute")
	}
	if msg.MessageType == "" {
		t.Errorf("expected MessageType attribute")
	}
	if len(msg.SenderNonce) == 0 {
		t.Errorf("expected SenderNonce attribute")
	}
}

func TestDecryptPKIEnvelope(t *testing.T) {
	pkcsReq := loadTestFile(t, "testdata/PKCSReq.der")
	msg, err := scep.ParsePKIMessage(pkcsReq)
	if err != nil {
		t.Fatal(err)
	}
	cacert, cakey := loadCACredentials(t)
	err = msg.DecryptPKIEnvelope(cacert, cakey)
	if err != nil {
		t.Fatal(err)
	}
	if msg.CSRReqMessage.CSR == nil {
		t.Errorf("expected non-nil CSR field")
	}
}

func loadTestFile(t *testing.T, path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadCACredentials(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	cert, err := loadCertFromFile("testdata/testca/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadKeyFromFile("testdata/testca/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func loadClientCredentials(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	cert, err := loadCertFromFile("testdata/testclient/client.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadKeyFromFile("testdata/testclient/client.key")
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func loadCertFromFile(path string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}

// load an encrypted private key from disk
func loadKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	// testca key has a password
	if len(pemBlock.Headers) > 0 {
		password := []byte("")
		b, err := x509.DecryptPEMBlock(pemBlock, password)
		if err != nil {
			return nil, err
		}
		return x509.ParsePKCS1PrivateKey(b)
	}

	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)

}
