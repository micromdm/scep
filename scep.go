package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/groob/pkcs7"
)

// SCEP OIDs
var (
	oidSCEPmessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPpkiStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPfailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPsenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPrecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPtransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// MessageType is a SCEP message type
type MessageType string

// Message Types
const (
	CertRep    MessageType = "3"
	RenewalReq             = "17"
	UpdateReq              = "18"
	PKCSReq                = "19"
	CertPoll               = "20"
	GetCert                = "21"
	GetCRL                 = "22"
)

// PKIStatus is a SCEP pkiStatus
type PKIStatus string

// PKI Statuses
const (
	SUCCESS PKIStatus = "0"
	FAILURE           = "2"
	PENDING           = "3"
)

// FailInfo is a SCEP failInfo type
type FailInfo string

// failinfos
const (
	BadAlg          FailInfo = "0"
	BadMessageCheck          = "1"
	BadRequest               = "2"
	BadTime                  = "3"
	BadCertID                = "4"
)

type pkiMessage struct {
	raw              []byte // the original content
	envelopedContent []byte // the encrypted part of the msg
	decryptedContent []byte

	messageType    MessageType
	pkiStatus      PKIStatus
	transactionID  string
	senderNonce    []byte
	recipientNonce []byte
	csr            *x509.CertificateRequest
	crtBytes       []byte
	repDegenerate  []byte
	recipients     []*x509.Certificate
	signedCert     *x509.Certificate
}

func parsePKIMessage(data []byte) (*pkiMessage, error) {
	// parse pkcs#7 signed data
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	var msgType MessageType
	err = p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msgType)
	if err != nil {
		return nil, err
	}
	var tID string
	err = p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &tID)
	if err != nil {
		return nil, err
	}
	var sn []byte
	err = p7.UnmarshalSignedAttribute(oidSCEPsenderNonce, &sn)
	if err != nil {
		return nil, err
	}
	// the csr is encrypted in the content of the pkcs#7 content
	msg := &pkiMessage{
		raw:              data,
		envelopedContent: p7.Content,
		messageType:      msgType,
		transactionID:    tID,
		senderNonce:      sn,
		recipients:       p7.Certificates,
	}
	return msg, nil
}

func (msg *pkiMessage) decrypt(cert *x509.Certificate, key *rsa.PrivateKey) error {
	p7, err := pkcs7.Parse(msg.envelopedContent)
	if err != nil {
		return err
	}
	data, err := p7.Decrypt(cert, key)
	if err != nil {
		return err
	}
	msg.decryptedContent = data

	//parse csr
	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return err
	}
	msg.csr = csr
	return nil
}

var (
	// Build CA based on RFC5280
	hostTemplate = x509.Certificate{
		// **SHOULD** be filled in a unique number
		SerialNumber: big.NewInt(4),
		// **SHOULD** be filled in host info
		Subject: pkix.Name{},
		// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
		NotBefore: time.Now().Add(-600).UTC(),
		// 10-year lease
		NotAfter: time.Time{},
		// Used for certificate signing only
		KeyUsage: 0,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		UnknownExtKeyUsage: nil,

		// activate CA
		BasicConstraintsValid: false,

		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		// **SHOULD** be filled in later
		SubjectKeyId: nil,

		// Subject Alternative Name
		DNSNames: nil,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}
)

func (msg *pkiMessage) signCert(crtAuth *x509.Certificate, keyAuth *rsa.PrivateKey) error {
	id, err := GenerateSubjectKeyID(msg.csr.PublicKey)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      msg.csr.Subject,
		NotBefore:    time.Now().Add(-600).UTC(),
		NotAfter:     time.Now().AddDate(1, 0, 0).UTC(),
		SubjectKeyId: id,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
			x509.ExtKeyUsageClientAuth,
		},
	}
	crt, err := x509.CreateCertificate(rand.Reader, tmpl, crtAuth, msg.csr.PublicKey, keyAuth)
	if err != nil {
		return err
	}
	msg.signedCert, err = x509.ParseCertificate(crt)
	if err != nil {
		return err
	}
	msg.crtBytes = crt
	return nil
}

func (msg *pkiMessage) CertRep() (*pkiMessage, error) {
	certs := []*x509.Certificate{msg.signedCert}
	deg, err := pkcs7.DegenerateCertificates(certs)
	if err != nil {
		return nil, err
	}

	reply := &pkiMessage{
		messageType:    CertRep,
		senderNonce:    msg.senderNonce,
		recipientNonce: msg.senderNonce,
		transactionID:  msg.transactionID,
		pkiStatus:      SUCCESS,
		repDegenerate:  deg,
		recipients:     msg.recipients,
	}
	return reply, nil
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// ID is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
