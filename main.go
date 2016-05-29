package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/groob/pkcs7"
)

func main() {
	http.HandleFunc("/scep", scepHandler)
	log.Fatal(http.ListenAndServe(":9001", nil))
}

const (
	certificatePEMBlockType = "CERTIFICATE"
)

func scepHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, ok := q["operation"]; !ok {
		fmt.Println("no operation in query parameters, returning")
	}
	op := q.Get("operation")
	switch op {
	case "GetCACaps":
		caps := []byte(`GetNextCACert
POSTPKIOperation`)
		w.Write(caps)
	case "GetCACert":
		c, err := loadPEMCertFromFile("testca/ca.crt")
		if err != nil {
			fmt.Println(err)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
		chain, err := pkcs7.DegenerateCertificates([]*x509.Certificate{c})
		if err != nil {
			fmt.Println(err)
			return
		}
		w.Write(chain)
		// c, err := loadPEMCertFromFile("/Users/vvrantch/code/go/src/github.com/micromdm/scep/ca/ca.crt")
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }
		// w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		// w.Write(c.Raw)
		return
	case "PKIOperation":
		handlePKIOperation(w, r)
	default:
		fmt.Println(r)
		fmt.Printf("unknown op type: %s\n", op)
		io.Copy(os.Stdout, r.Body)
	}
}

func handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	k := key()
	c := cert()
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile("request", data, 0755)
	msg, err := parsePKIMessage(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = msg.decrypt(c, k)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = msg.signCert(c, k)
	if err != nil {
		fmt.Println(err)
		return
	}
	reply, err := msg.CertRep()
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile("device.crt", msg.crtBytes, 0755)
	ioutil.WriteFile("degenerate", reply.repDegenerate, 0755)
	e7, err := pkcs7.Encrypt(reply.repDegenerate, reply.recipients)
	if err != nil {
		fmt.Println(err)
		return
	}
	sd, err := pkcs7.NewSignedData(e7)
	if err != nil {
		fmt.Println(err)
		return
	}
	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			pkcs7.Attribute{
				Type:  oidSCEPpkiStatus,
				Value: reply.pkiStatus,
			},
			pkcs7.Attribute{
				Type:  oidSCEPmessageType,
				Value: reply.messageType,
			},
			pkcs7.Attribute{
				Type:  oidSCEPtransactionID,
				Value: reply.transactionID,
			},
			// pkcs7.Attribute{
			// 	Type:  oidSCEPsenderNonce,
			// 	Value: reply.senderNonce,
			// },
			pkcs7.Attribute{
				Type:  oidSCEPrecipientNonce,
				Value: reply.recipientNonce,
			},
		},
	}
	cert, err := x509.ParseCertificate(msg.crtBytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	sd.AddCertificate(cert)
	err = sd.AddSigner(c, k, config)
	if err != nil {
		fmt.Println(err)
		return
	}
	response, err := sd.Finish()
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile("response", response, 0755)
	w.Header().Set("Content-Type", "application/x-pki-message")
	w.Write(response)
	pd, err := pkcs7.Parse(response)
	if err != nil {
		log.Fatal(err)
	}
	_ = pd
	return
}

func loadPEMCertFromFile(path string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != certificatePEMBlockType || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}
	crt, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

// helpers
func key() *rsa.PrivateKey {
	data, err := ioutil.ReadFile("testca/ca.key")
	if err != nil {
		log.Fatal(err)
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		log.Fatal("PEM decode failed")
	}
	password := []byte("")
	b, err := x509.DecryptPEMBlock(pemBlock, password)
	if err != nil {
		log.Fatal(err)
	}
	k, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		fmt.Println("keyfail")
		log.Fatal(err)
	}
	return k
}

func cert() *x509.Certificate {
	data, err := ioutil.ReadFile("testca/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		log.Fatal("PEM decode failed")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return cert
}
