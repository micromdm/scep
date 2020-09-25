package scepserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	kitlog "github.com/go-kit/kit/log"

	"github.com/micromdm/scep/depot"
	filedepot "github.com/micromdm/scep/depot/file"
	scepserver "github.com/micromdm/scep/server"
)

func TestCACaps(t *testing.T) {
	server, _, teardown := newServer(t)
	defer teardown()
	url := server.URL + "/scep?operation=GetCACaps"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Error("expected", http.StatusOK, "got", resp.StatusCode)
	}
}

func TestEncodePKCSReq_Request(t *testing.T) {
	pkcsreq := loadTestFile(t, "../scep/testdata/PKCSReq.der")
	msg := scepserver.SCEPRequest{
		Operation: "PKIOperation",
		Message:   pkcsreq,
	}
	methods := []string{"POST", "GET"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "http://acme.co/scep", nil)
			rr := *r
			if err := scepserver.EncodeSCEPRequest(context.Background(), &rr, msg); err != nil {
				t.Fatal(err)
			}

			q := r.URL.Query()
			if have, want := q.Get("operation"), msg.Operation; have != want {
				t.Errorf("have %s, want %s", have, want)
			}

			if method == "POST" {
				if have, want := rr.ContentLength, int64(len(msg.Message)); have != want {
					t.Errorf("have %d, want %d", have, want)
				}
			}

			if method == "GET" {
				if q.Get("message") == "" {
					t.Errorf("expected GET PKIOperation to have a non-empty message field")
				}
			}

		})
	}

}

func TestPKIOperation(t *testing.T) {
	server, _, teardown := newServer(t)
	defer teardown()
	pkcsreq := loadTestFile(t, "../scep/testdata/PKCSReq.der")
	body := bytes.NewReader(pkcsreq)
	url := server.URL + "/scep?operation=PKIOperation"
	resp, err := http.Post(url, "", body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Error("expected", http.StatusOK, "got", resp.StatusCode)
	}
}

func TestPKIOperationGET(t *testing.T) {
	server, _, teardown := newServer(t)
	defer teardown()
	pkcsreq := loadTestFile(t, "../scep/testdata/PKCSReq.der")
	message := base64.StdEncoding.EncodeToString(pkcsreq)
	req, err := http.NewRequest("GET", server.URL + "/scep", nil)
	if err != nil {
		t.Fatal(err)
	}
	params := req.URL.Query()
	params.Set("operation", "PKIOperation")
	params.Set("message", message)
	req.URL.RawQuery = params.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Error("expected", http.StatusOK, "got", resp.StatusCode)
	}
}

func newServer(t *testing.T, opts ...scepserver.ServiceOption) (*httptest.Server, scepserver.Service, func()) {
	var err error
	var depot depot.Depot // cert storage
	{
		depot, err = filedepot.NewFileDepot("../scep/testdata/testca")
		if err != nil {
			t.Fatal(err)
		}
		depot = &noopDepot{depot}
	}
	var svc scepserver.Service // scep service
	{
		svc, err = scepserver.NewService(depot, opts...)
		if err != nil {
			t.Fatal(err)
		}
	}
	logger := kitlog.NewNopLogger()
	e := scepserver.MakeServerEndpoints(svc)
	handler := scepserver.MakeHTTPHandler(e, svc, logger)
	server := httptest.NewServer(handler)
	teardown := func() {
		server.Close()
		os.Remove("../scep/testdata/testca/serial")
		os.Remove("../scep/testdata/testca/index.txt")
	}
	return server, svc, teardown
}

type noopDepot struct{ depot.Depot }

func (d *noopDepot) Put(name string, crt *x509.Certificate) error {
	return nil
}

/* helpers */
const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func loadTestFile(t *testing.T, path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// create a new RSA private key
func newRSAKey(bits int) (*rsa.PrivateKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return private, nil
}

// create a CSR using the same parameters as Keychain Access would produce
func newCSR(priv *rsa.PrivateKey, email, country, cname string) ([]byte, error) {
	subj := pkix.Name{
		Country:    []string{country},
		CommonName: cname,
		ExtraNames: []pkix.AttributeTypeAndValue{pkix.AttributeTypeAndValue{
			Type:  []int{1, 2, 840, 113549, 1, 9, 1},
			Value: email,
		}},
	}
	template := &x509.CertificateRequest{
		Subject: subj,
	}
	return x509.CreateCertificateRequest(rand.Reader, template, priv)
}
func loadCACredentials(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	cert, err := loadCertFromFile("../scep/testdata/testca/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadKeyFromFile("../scep/testdata/testca/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func loadClientCredentials(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	cert, err := loadCertFromFile("../scep/testdata/testclient/client.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadKeyFromFile("../scep/testdata/testclient/client.key")
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

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
