package main

import (
	"crypto/md5"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/micromdm/scep/client"
	"github.com/micromdm/scep/scep"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

// version info
var (
	version = "unreleased"
	gitHash = "unknown"
)

type runCfg struct {
	dir          string
	csrPath      string
	keyPath      string
	keyBits      int
	selfSignPath string
	certPath     string
	cn           string
	org          string
	ou           string
	locality     string
	province     string
	country      string
	challenge    string
	serverURL    string
	caMD5        string
}

func isAsciiPrintableTo(s string) int {
	count := 0
	for _, r := range s {
		count = count + 1
		if r > unicode.MaxLatin1 || !unicode.IsPrint(r) {
			return count - 1
		}
	}
	return count - 1
}

func run(cfg runCfg) error {
	key, err := loadOrMakeKey(cfg.keyPath, cfg.keyBits)
	if err != nil {
		return err
	}

	opts := &csrOptions{
		cn:        cfg.cn,
		org:       cfg.org,
		country:   strings.ToUpper(cfg.country),
		ou:        cfg.ou,
		locality:  cfg.locality,
		province:  cfg.province,
		challenge: cfg.challenge,
		key:       key,
	}

	csr, err := loadOrMakeCSR(cfg.csrPath, opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var self *x509.Certificate
	cert, err := loadPEMCertFromFile(cfg.certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		s, err := loadOrSign(cfg.selfSignPath, key, csr)
		if err != nil {
			return err
		}
		self = s
	}

	ctx := context.Background()
	var client scepclient.Client
	{
		client = scepclient.NewClient(cfg.serverURL)
	}

	resp, certNum, err := client.GetCACert(ctx)
	if err != nil {
		return err
	}
	var certs []*x509.Certificate
	{
		if certNum > 1 {
			certs, err = scep.CACerts(resp)
			if err != nil {
				return err
			}
			if len(certs) < 1 {
				return fmt.Errorf("no certificates returned")
			}
		} else {
			certs, err = x509.ParseCertificates(resp)
			if err != nil {
				return err
			}
		}
	}

	var signerCert *x509.Certificate
	{
		if cert != nil {
			signerCert = cert
		} else {
			signerCert = self
		}
	}

	var msgType scep.MessageType
	{
		// TODO validate CA and set UpdateReq if needed
		if cert != nil {
			msgType = scep.RenewalReq
		} else {
			msgType = scep.PKCSReq
		}
	}

	var recipients []*x509.Certificate
	if cfg.caMD5 == "" {
		recipients = certs
	} else {
		r, err := findRecipients(cfg.caMD5, certs)
		if err != nil {
			return err
		}
		recipients = r
	}

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  recipients,
		SignerKey:   key,
		SignerCert:  signerCert,
	}

	if cfg.challenge != "" && msgType == scep.PKCSReq {
		tmpl.CSRReqMessage = &scep.CSRReqMessage{
			ChallengePassword: cfg.challenge,
		}
	}

	msg, err := scep.NewCSRRequest(csr, tmpl)
	if err != nil {
		return errors.Wrap(err, "creating csr pkiMessage")
	}

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return errors.Wrapf(err, "PKIOperation for %s", msgType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes)
		if err != nil {
			return errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			log.Println("pkiStatus PENDING: sleeping for 30 seconds, then trying again.")
			time.Sleep(30 * time.Second)
			continue
		}
		log.Println("pkiStatus SUCCESS: server returned a certificate.")
		break // on scep.SUCCESS
	}

	if err := respMsg.DecryptPKIEnvelope(signerCert, key); err != nil {
		return errors.Wrapf(err, "decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus)
	}

	respCert := respMsg.CertRepMessage.Certificate
	if err := ioutil.WriteFile(cfg.certPath, pemCert(respCert.Raw), 0666); err != nil {
		return err
	}

	// remove self signer if used
	if self != nil {
		if err := os.Remove(cfg.selfSignPath); err != nil {
			return err
		}
	}

	return nil
}

// Determine the correct recipient based on the fingerprint.
// In case of NDES that is the last certificate in the chain, not the RA cert.
// Return a full chain starting with the cert that matches the fingerprint.
func findRecipients(fingerprint string, certs []*x509.Certificate) ([]*x509.Certificate, error) {
	fingerprint = strings.Join(strings.Split(fingerprint, " "), "")
	fingerprint = strings.ToLower(fingerprint)
	for i, cert := range certs {
		sum := fmt.Sprintf("%x", md5.Sum(cert.Raw))
		if sum == fingerprint {
			return certs[i-1:], nil
		}
	}
	return nil, errors.Errorf("could not find cert for md5 %s", fingerprint)
}

func validateFlags(keyPath, serverURL string) error {
	if keyPath == "" {
		return errors.New("must specify private key path")
	}
	if serverURL == "" {
		return errors.New("must specify server-url flag parameter")
	}
	_, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server-url flag parameter %s", err)
	}
	return nil
}

func main() {
	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flServerURL         = flag.String("server-url", "", "SCEP server url")
		flChallengePassword = flag.String("challenge", "", "enforce a challenge password")
		flPKeyPath          = flag.String("private-key", "", "private key path, if there is no key, scepclient will create one")
		flCertPath          = flag.String("certificate", "", "certificate path, if there is no key, scepclient will create one")
		flKeySize           = flag.Int("keySize", 2048, "rsa key size")
		flOrg               = flag.String("organization", "scep-client", "organization for cert")
		flCName             = flag.String("cn", "scepclient", "common name for certificate")
		flOU                = flag.String("ou", "MDM", "organizational unit for certificate")
		flLoc               = flag.String("locality", "", "locality for certificate")
		flProvince          = flag.String("province", "", "province for certificate")
		flCountry           = flag.String("country", "US", "country code in certificate")

		// in case of multiple certificate authorities, we need to figure out who the recipient of the encrypted
		// data is.
		flCAFingerprint = flag.String("ca-fingerprint", "", "md5 fingerprint of CA certificate for NDES server.")
	)
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Printf("scepclient - %v\n", version)
		fmt.Printf("git revision - %v\n", gitHash)
		os.Exit(0)
	}

	if err := validateFlags(*flPKeyPath, *flServerURL); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dir := filepath.Dir(*flPKeyPath)
	csrPath := dir + "/csr.pem"
	selfSignPath := dir + "/self.pem"
	if *flCertPath == "" {
		*flCertPath = dir + "/client.pem"
	}

	cfg := runCfg{
		dir:          dir,
		csrPath:      csrPath,
		keyPath:      *flPKeyPath,
		keyBits:      *flKeySize,
		selfSignPath: selfSignPath,
		certPath:     *flCertPath,
		cn:           *flCName,
		org:          *flOrg,
		country:      *flCountry,
		locality:     *flLoc,
		ou:           *flOU,
		province:     *flProvince,
		challenge:    *flChallengePassword,
		serverURL:    *flServerURL,
		caMD5:        *flCAFingerprint,
	}

	if err := run(cfg); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
