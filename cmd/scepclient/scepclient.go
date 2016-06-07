package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/context"

	"github.com/micromdm/scep/client"
	"github.com/micromdm/scep/scep"
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
	country      string
	challenge    string
	serverURL    string
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

	resp, err := client.GetCACert(ctx)
	if err != nil {
		return err
	}
	certs, err := scep.CACerts(resp)
	if err != nil {
		return err
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

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  certs,
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
		return err
	}

	respBytes, err := client.PKIOperation(ctx, msg.Raw)
	if err != nil {
		return err
	}
	respMsg, err := scep.ParsePKIMessage(respBytes)
	if err != nil {
		return err
	}
	if err := respMsg.DecryptPKIEnvelope(signerCert, key); err != nil {
		fmt.Println(err)
		os.Exit(1)
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
	// flags
	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flServerURL         = flag.String("server-url", "", "SCEP server url")
		flChallengePassword = flag.String("challenge", "", "enforce a challenge password")
		flPKeyPath          = flag.String("private-key", "", "private key path, if there is no key, scepclient will create one")
		flCertPath          = flag.String("certificate", "", "certificate path, if there is no key, scepclient will create one")
		flKeySize           = flag.Int("keySize", 2048, "rsa key size")
		flOrg               = flag.String("organization", "scep-client", "organization for cert")
		flCName             = flag.String("cn", "scepclient", "common name for certificate")
		flCountry           = flag.String("country", "US", "country code in certificate")
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
		challenge:    *flChallengePassword,
		serverURL:    *flServerURL,
	}

	if err := run(cfg); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
