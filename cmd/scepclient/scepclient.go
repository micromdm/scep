package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	scepclient "github.com/micromdm/scep/client"
	"github.com/micromdm/scep/scep"
	"github.com/pkg/errors"
)

// version info
var (
	version = "unknown"
)

type runCfg struct {
	dir            string
	csrPath        string
	keyPath        string
	keyBits        int
	selfSignPath   string
	certPath       string
	cn             string
	org            string
	ou             string
	locality       string
	province       string
	country        string
	challenge      string
	serverURL      string
	caCertSelector scep.CertsSelector
	debug          bool
	logfmt         string
	caCertMsg      string
}

func run(cfg runCfg) error {
	ctx := context.Background()
	var logger log.Logger
	{
		if strings.ToLower(cfg.logfmt) == "json" {
			logger = log.NewJSONLogger(os.Stderr)
		} else {
			logger = log.NewLogfmtLogger(os.Stderr)
		}
		stdlog.SetOutput(log.NewStdlibAdapter(logger))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		if !cfg.debug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
	}
	lginfo := level.Info(logger)

	client, err := scepclient.New(cfg.serverURL, logger)
	if err != nil {
		return err
	}

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

	resp, certNum, err := client.GetCACert(ctx, cfg.caCertMsg)
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
		} else {
			certs, err = x509.ParseCertificates(resp)
			if err != nil {
				return err
			}
		}
	}

	if cfg.debug {
		logCerts(level.Debug(logger), certs)
	}

	// pick the CA/RA cert based on our CertSelector
	recipients := cfg.caCertSelector.SelectCerts(certs)
	if len(recipients) < 1 {
		return errors.New("no CA/RA certificates found")
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
		Recipients:  recipients,
		SignerKey:   key,
		SignerCert:  signerCert,
	}

	if cfg.challenge != "" && msgType == scep.PKCSReq {
		tmpl.CSRReqMessage = &scep.CSRReqMessage{
			ChallengePassword: cfg.challenge,
		}
	}

	msg, err := scep.NewCSRRequest(csr, tmpl, scep.WithLogger(logger))
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

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(logger), scep.WithCACerts(recipients))
		if err != nil {
			return errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			lginfo.Log("pkiStatus", "PENDING", "msg", "sleeping for 30 seconds, then trying again.")
			time.Sleep(30 * time.Second)
			continue
		}
		lginfo.Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")
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

// logCerts logs the count, number, RDN, and SHA-256 of certs to logger
func logCerts(logger log.Logger, certs []*x509.Certificate) {
	logger.Log("msg", "cacertlist", "count", len(certs))
	for i, cert := range certs {
		logger.Log(
			"msg", "cacertlist",
			"number", i,
			"rdn", cert.Subject.ToRDNSequence().String(),
			"sha256", fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
		)
	}
}

// sha256FingerprintCertsSelector returns a CertsSelector that matches a SHA-256 fingerprint
func sha256FingerprintCertsSelector(fingerprint string) scep.CertsSelectorFunc {
	fingerprint = strings.Join(strings.Split(fingerprint, " "), "")
	fingerprint = strings.ToLower(fingerprint)
	return func(certs []*x509.Certificate) (selected []*x509.Certificate) {
		for _, cert := range certs {
			sum := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
			if sum == fingerprint {
				selected = append(selected, cert)
				return
			}
		}
		return
	}
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
		flCACertMessage     = flag.String("cacert-message", "", "message sent with GetCACert operation")

		// in case of multiple certificate authorities, we need to figure out who the recipient of the encrypted
		// data is.
		flCAFingerprint = flag.String("ca-fingerprint", "", "SHA-256 digest of CA certificate for NDES server. Note: Changed from MD5.")

		flDebugLogging = flag.Bool("debug", false, "enable debug logging")
		flLogJSON      = flag.Bool("log-json", false, "use JSON for log output")
	)
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Println(version)
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
	var logfmt string
	if *flLogJSON {
		logfmt = "json"
	}

	cfg := runCfg{
		dir:            dir,
		csrPath:        csrPath,
		keyPath:        *flPKeyPath,
		keyBits:        *flKeySize,
		selfSignPath:   selfSignPath,
		certPath:       *flCertPath,
		cn:             *flCName,
		org:            *flOrg,
		country:        *flCountry,
		locality:       *flLoc,
		ou:             *flOU,
		province:       *flProvince,
		challenge:      *flChallengePassword,
		serverURL:      *flServerURL,
		caCertSelector: scep.NopCertsSelector(),
		debug:          *flDebugLogging,
		logfmt:         logfmt,
		caCertMsg:      *flCACertMessage,
	}

	if *flCAFingerprint != "" {
		cfg.caCertSelector = sha256FingerprintCertsSelector(*flCAFingerprint)
	}

	if err := run(cfg); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
