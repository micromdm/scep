package scepserver

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"bufio"
	"io"
	"strings"
	"fmt"
	"bytes"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
)

// Depot is a repository for managing certificates
type Depot interface {
	CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error)
	Put(name string, crt *x509.Certificate) error
	Serial() (*big.Int, error)
	dbHasCn(cn string, cert *x509.Certificate) error
}

// NewFileDepot returns a new cert depot
func NewFileDepot(path string) (Depot, error) {
	return fileDepot{dirPath: path}, nil
}

type fileDepot struct {
	dirPath string
}

func (d fileDepot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	caPEM, err := d.getFile("ca.pem")
	if err != nil {
		return nil, nil, err
	}
	cert, err := loadCert(caPEM.Data)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := d.getFile("ca.key")
	if err != nil {
		return nil, nil, err
	}
	key, err := loadKey(keyPEM.Data, pass)
	if err != nil {
		return nil, nil, err
	}
	return []*x509.Certificate{cert}, key, nil
}

// file permissions
const (
	certPerm   = 0444
	serialPerm = 0400
	dbPerm = 0600
)

// Put adds a certificate to the depot
func (d fileDepot) Put(cn string, crt *x509.Certificate) error {
	if crt == nil {
		return errors.New("crt is nil")
	}
	if crt.Raw == nil {
		return errors.New("data is nil")
	}
	data := crt.Raw;

	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}

	serial, err := d.Serial()
	if err != nil {
		return err
	}

	name := d.path(cn) + "." + serial.String() + ".pem"
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, certPerm)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(data)); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	if err := d.writeDB(cn, serial, cn+"."+serial.String()+".pem", crt); err != nil {
		return err
	}

	if err := d.incrementSerial(serial); err != nil {
		return err
	}

	return nil
}

func (d fileDepot) Serial() (*big.Int, error) {
	name := d.path("serial")
	s := big.NewInt(2)
	if err := d.check("serial"); err != nil {
		// assuming it doesnt exist, create
		if err := d.writeSerial(s); err != nil {
			return nil, err
		}
		return s, nil
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	r := bufio.NewReader(file)
	data, err := r.ReadString('\r')
	if err != nil && err != io.EOF {
		return nil, err
	}
	data = strings.TrimSuffix(data ,"\r")
	data = strings.TrimSuffix(data ,"\n")
	serial, ok := s.SetString(data,16)
	if !ok {
		return nil, errors.New("could not convert "+string(data)+" to serial number")
	}
	return serial, nil
}

func makeDn(cert *x509.Certificate) string {
	var dn bytes.Buffer
	
	if len(cert.Subject.Country) >0 && len(cert.Subject.Country[0]) > 0 {
		dn.WriteString("/C=" + cert.Subject.Country[0])
	}
	if len(cert.Subject.Province) > 0 && len(cert.Subject.Province[0]) > 0 {
		dn.WriteString("/ST=" + cert.Subject.Province[0])
	}
	if len(cert.Subject.Locality) >0 && len(cert.Subject.Locality[0]) > 0 {
		dn.WriteString("/L=" + cert.Subject.Locality[0])
	}
	if len(cert.Subject.Organization) >0 && len(cert.Subject.Organization[0]) > 0 {
		dn.WriteString("/O=" + cert.Subject.Organization[0])
	}
	if len(cert.Subject.OrganizationalUnit) >0 && len(cert.Subject.OrganizationalUnit[0]) > 0 {
		dn.WriteString("/OU=" + cert.Subject.OrganizationalUnit[0])
	}
	if len(cert.Subject.CommonName) >0 {
		dn.WriteString("/CN="+cert.Subject.CommonName)
	}
	if len(cert.EmailAddresses) >0 {
		dn.WriteString("/emailAddress=" + cert.EmailAddresses[0])
	}
	return dn.String();
}

// Determine if the cadb already has a valid certificate with the same name
func (d fileDepot) dbHasCn(cn string, cert *x509.Certificate) error {
	
	dn := makeDn(cert)

	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}
	name := d.path("index.txt")
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if(strings.HasSuffix(scanner.Text(), dn)){
			// Determine if DN starts with V (valid)
			if(strings.HasPrefix(scanner.Text(), "V\t")){
				return errors.New("DN "+dn+" already exists");
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}  
	return nil
}

func (d fileDepot) writeDB(cn string, serial *big.Int, filename string, cert *x509.Certificate) error {

	var dbEntry bytes.Buffer

	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}
	name := d.path("index.txt")

	file, err := os.OpenFile(name, os.O_CREATE | os.O_RDWR | os.O_APPEND, dbPerm)
	if err != nil {
		return fmt.Errorf("could not append to "+name+" : %q\n", err.Error())
	}
	defer file.Close()

	// Format of the caDB, see http://pki-tutorial.readthedocs.io/en/latest/cadb.html
	//   STATUSFLAG  EXPIRATIONDATE  REVOCATIONDATE(or emtpy)	SERIAL_IN_HEX   CERTFILENAME_OR_'unknown'   Certificate_DN

	serialHex  := fmt.Sprintf("%x", cert.SerialNumber)
	t := cert.NotAfter
	y := (int(t.Year()) % 100)
	validDate := fmt.Sprintf("%02d%02d%02d%02d%02d%02dZ", y, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	dn := makeDn(cert)

	// Valid
	dbEntry.WriteString("V\t")
	// Valid till
	dbEntry.WriteString(validDate+"\t")
	// Emptry (not revoked)
	dbEntry.WriteString("\t")
	// Serial in Hex
	dbEntry.WriteString(serialHex+"\t")
	// Certificate file name
	dbEntry.WriteString(filename+"\t")
	// Certificate DN
	dbEntry.WriteString(dn);
	dbEntry.WriteString("\n")

	if _, err := file.Write(dbEntry.Bytes()); err != nil {
		return err
	}
	return nil
}


func (d fileDepot) writeSerial(serial *big.Int) error {
	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}
	name := d.path("serial")
	os.Remove(name)

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, serialPerm)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(fmt.Sprintf("%x\n",serial.Bytes())); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}
	return nil
}

// read serial and increment
func (d fileDepot) incrementSerial(s *big.Int) error {
	serial := s.Add(s, big.NewInt(1))
	if err := d.writeSerial(serial); err != nil {
		return err
	}
	return nil
}

type file struct {
	Info os.FileInfo
	Data []byte
}

func (d *fileDepot) check(path string) error {
	name := d.path(path)
	_, err := os.Stat(name)
	if err != nil {
		return err
	}
	return nil
}

func (d *fileDepot) getFile(path string) (*file, error) {
	if err := d.check(path); err != nil {
		return nil, err
	}
	fi, err := os.Stat(d.path(path))
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(d.path(path))
	return &file{fi, b}, err
}

func (d *fileDepot) path(name string) string {
	return filepath.Join(d.dirPath, name)
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

// load an encrypted private key from disk
func loadKey(data []byte, password []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	b, err := x509.DecryptPEMBlock(pemBlock, password)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(b)
}

// load an encrypted private key from disk
func loadCert(data []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:	certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}
