package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/micromdm/scep/cryptoutil"
	"github.com/micromdm/scep/csrverifier"
	executablecsrverifier "github.com/micromdm/scep/csrverifier/executable"
	scepdepot "github.com/micromdm/scep/depot"
	"github.com/micromdm/scep/depot/file"
	scepserver "github.com/micromdm/scep/server"
)

// version info
var (
	version = "unreleased"
	gitHash = "unknown"
)

func main() {
	var caCMD = flag.NewFlagSet("ca", flag.ExitOnError)
	{
		if len(os.Args) >= 2 {
			if os.Args[1] == "ca" {
				status := caMain(caCMD)
				os.Exit(status)
			}
		}
	}

	//main flags
	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flPort              = flag.String("port", envString("SCEP_HTTP_LISTEN_PORT", "8080"), "port to listen on")
		flDepotPath         = flag.String("depot", envString("SCEP_FILE_DEPOT", "depot"), "path to ca folder")
		flCAPass            = flag.String("capass", envString("SCEP_CA_PASS", ""), "passwd for the ca.key")
		flClDuration        = flag.String("crtvalid", envString("SCEP_CERT_VALID", "365"), "validity for new client certificates in days")
		flClAllowRenewal    = flag.String("allowrenew", envString("SCEP_CERT_RENEW", "14"), "do not allow renewal until n days before expiry, set to 0 to always allow")
		flChallengePassword = flag.String("challenge", envString("SCEP_CHALLENGE_PASSWORD", ""), "enforce a challenge password")
		flCSRVerifierExec   = flag.String("csrverifierexec", envString("SCEP_CSR_VERIFIER_EXEC", ""), "will be passed the CSRs for verification")
		flDebug             = flag.Bool("debug", envBool("SCEP_LOG_DEBUG"), "enable debug logging")
		flLogJSON           = flag.Bool("log-json", envBool("SCEP_LOG_JSON"), "output JSON logs")
	)
	flag.Usage = func() {
		flag.PrintDefaults()

		fmt.Println("usage: scep [<command>] [<args>]")
		fmt.Println(" ca <args> create/manage a CA")
		fmt.Println("type <command> --help to see usage for each subcommand")
	}
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Printf("scep - %v\n", version)
		fmt.Printf("git revision - %v\n", gitHash)
		os.Exit(0)
	}
	port := ":" + *flPort

	var logger log.Logger
	{

		if *flLogJSON {
			logger = log.NewJSONLogger(os.Stderr)
		} else {
			logger = log.NewLogfmtLogger(os.Stderr)
		}
		if !*flDebug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	lginfo := level.Info(logger)

	var err error
	var depot scepdepot.Depot // cert storage
	{
		depot, err = file.NewFileDepot(*flDepotPath)
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
	}
	allowRenewal, err := strconv.Atoi(*flClAllowRenewal)
	if err != nil {
		lginfo.Log("err", err, "msg", "No valid number for allowed renewal time")
		os.Exit(1)
	}
	clientValidity, err := strconv.Atoi(*flClDuration)
	if err != nil {
		lginfo.Log("err", err, "msg", "No valid number for client cert validity")
		os.Exit(1)
	}
	var csrVerifier csrverifier.CSRVerifier
	if *flCSRVerifierExec > "" {
		executableCSRVerifier, err := executablecsrverifier.New(*flCSRVerifierExec, lginfo)
		if err != nil {
			lginfo.Log("err", err, "msg", "Could not instantiate CSR verifier")
			os.Exit(1)
		}
		csrVerifier = executableCSRVerifier
	}

	var svc scepserver.Service // scep service
	{
		svcOptions := []scepserver.ServiceOption{
			scepserver.WithLogger(logger),
		}
		if *flChallengePassword != "" {
			svcOptions = append(svcOptions, scepserver.WithStaticChallengePassword(*flChallengePassword))
		}
		if csrVerifier != nil {
			svcOptions = append(svcOptions, scepserver.WithCSRSignerMiddleware(csrverifier.NewCSRSignerMiddleware(csrVerifier)))
		}
		crts, key, err := depot.CA([]byte(*flCAPass))
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
		if len(crts) < 1 {
			lginfo.Log("err", "missing CA certificate")
			os.Exit(1)
		}
		signer := scepdepot.CSRSigner(depot, allowRenewal, clientValidity, *flCAPass)
		svc, err = scepserver.NewService(crts[0], key, signer, svcOptions...)
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
		svc = scepserver.NewLoggingService(log.With(lginfo, "component", "scep_service"), svc)
	}

	var h http.Handler // http handler
	{
		e := scepserver.MakeServerEndpoints(svc)
		e.GetEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.GetEndpoint)
		e.PostEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.PostEndpoint)
		h = scepserver.MakeHTTPHandler(e, svc, log.With(lginfo, "component", "http"))
	}

	// start http server
	errs := make(chan error, 2)
	go func() {
		lginfo.Log("transport", "http", "address", port, "msg", "listening")
		errs <- http.ListenAndServe(port, h)
	}()
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	lginfo.Log("terminated", <-errs)
}

func caMain(cmd *flag.FlagSet) int {
	var (
		flDepotPath = cmd.String("depot", "depot", "path to ca folder")
		flInit      = cmd.Bool("init", false, "create a new CA")
		flYears     = cmd.Int("years", 10, "default CA years")
		flKeySize   = cmd.Int("keySize", 4096, "rsa key size")
		flOrg       = cmd.String("organization", "scep-ca", "organization for CA cert")
		flOrgUnit   = cmd.String("organizational_unit", "SCEP CA", "organizational unit (OU) for CA cert")
		flPassword  = cmd.String("key-password", "", "password to store rsa key")
		flCountry   = cmd.String("country", "US", "country for CA cert")
	)
	cmd.Parse(os.Args[2:])
	if *flInit {
		fmt.Println("Initializing new CA")
		key, err := createKey(*flKeySize, []byte(*flPassword), *flDepotPath)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		if err := createCertificateAuthority(key, *flYears, *flOrg, *flOrgUnit, *flCountry, *flDepotPath); err != nil {
			fmt.Println(err)
			return 1
		}
	}

	return 0
}

// create a key, save it to depot and return it for further usage.
func createKey(bits int, password []byte, depot string) (*rsa.PrivateKey, error) {
	// create depot folder if missing
	if err := os.MkdirAll(depot, 0755); err != nil {
		return nil, err
	}
	name := filepath.Join(depot, "ca.key")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// create RSA key and save as PEM file
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	privPEMBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		rsaPrivateKeyPEMBlockType,
		x509.MarshalPKCS1PrivateKey(key),
		password,
		x509.PEMCipher3DES,
	)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(file, privPEMBlock); err != nil {
		os.Remove(name)
		return nil, err
	}

	return key, nil
}

func createCertificateAuthority(key *rsa.PrivateKey, years int, organization string, organizationalUnit string, country string, depot string) error {
	var (
		authPkixName = pkix.Name{
			Country:            nil,
			Organization:       nil,
			OrganizationalUnit: nil,
			Locality:           nil,
			Province:           nil,
			StreetAddress:      nil,
			PostalCode:         nil,
			SerialNumber:       "",
			CommonName:         "",
		}
		// Build CA based on RFC5280
		authTemplate = x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      authPkixName,
			// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
			NotBefore: time.Now().Add(-600).UTC(),
			NotAfter:  time.Time{},
			// Used for certificate signing only
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

			ExtKeyUsage:        nil,
			UnknownExtKeyUsage: nil,

			// activate CA
			BasicConstraintsValid: true,
			IsCA:                  true,
			// Not allow any non-self-issued intermediate CA
			MaxPathLen: 0,

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

	subjectKeyID, err := cryptoutil.GenerateSubjectKeyID(&key.PublicKey)
	if err != nil {
		return err
	}
	authTemplate.SubjectKeyId = subjectKeyID
	authTemplate.NotAfter = time.Now().AddDate(years, 0, 0).UTC()
	authTemplate.Subject.Country = []string{country}
	authTemplate.Subject.Organization = []string{organization}
	authTemplate.Subject.OrganizationalUnit = []string{organizationalUnit}
	crtBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, &authTemplate, &key.PublicKey, key)
	if err != nil {
		return err
	}

	name := filepath.Join(depot, "ca.pem")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(crtBytes)); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	return nil
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

func envBool(key string) bool {
	if env := os.Getenv(key); env == "true" {
		return true
	}
	return false
}
