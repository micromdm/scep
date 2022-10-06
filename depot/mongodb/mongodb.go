package mongodb

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDBStorage struct {
	MongoClient            *mongo.Client
	CACollection           *mongo.Collection
	IssuedCertsCollection  *mongo.Collection
	SerialNumberCollection *mongo.Collection
}

// TODO - Enable configuration of these names
const (
	databaseName = "scep"

	caStoreName           = "ca_store"
	issuedCertStoreName   = "issued_certificates_store"
	serialNumberStoreName = "serial_number_store"
)

func New(ctx context.Context, uri string, username string, password string) (*MongoDBStorage, error) {
	var err error
	storage := &MongoDBStorage{}

	mongoOpts := options.Client().ApplyURI(uri)
	mongoOpts.SetAuth(options.Credential{Username: username, Password: password})

	storage.MongoClient, err = mongo.NewClient(mongoOpts)
	if err != nil {
		return nil, err
	}

	err = storage.MongoClient.Connect(ctx)
	if err != nil {
		return nil, err
	}

	storage.CACollection = storage.MongoClient.Database(databaseName).Collection(caStoreName)
	storage.IssuedCertsCollection = storage.MongoClient.Database(databaseName).Collection(issuedCertStoreName)
	storage.SerialNumberCollection = storage.MongoClient.Database(databaseName).Collection(serialNumberStoreName)

	return storage, nil
}

type CAEntry struct {
	Certificates []string `bson:"certificates,omitempty"`
	PrivateKey   string   `bson:"private_key,omitempty"`
}

func (m MongoDBStorage) SeedCA(certs []string, key string) error {

	upsert := true
	filter := bson.M{}
	update := bson.M{
		"$set": CAEntry{
			Certificates: certs,
			PrivateKey:   key,
		},
	}

	_, err := m.CACollection.UpdateOne(context.TODO(), filter, update, options.Update().SetUpsert(upsert))

	return err
}

func (m *MongoDBStorage) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	certs := []*x509.Certificate{}

	latestSort := bson.M{
		"$natural": -1,
	}
	filter := bson.M{}

	res := CAEntry{}
	err := m.CACollection.FindOne(context.TODO(), filter, options.FindOne().SetSort(latestSort)).Decode(&res)
	if err != nil {
		return certs, nil, err
	}

	for _, v := range res.Certificates {
		pemBlock, _ := pem.Decode([]byte(v))
		if pemBlock == nil {
			return certs, nil, errors.New("PEM decode failed")
		}
		if pemBlock.Type != "CERTIFICATE" {
			return certs, nil, errors.New("unmatched type or headers")
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return certs, nil, err
		}

		certs = append(certs, cert)
	}

	pemBlock, _ := pem.Decode([]byte(res.PrivateKey))
	if pemBlock == nil {
		return certs, nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return certs, nil, errors.New("unmatched type or headers")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey([]byte(pemBlock.Bytes))
	if err != nil {
		return certs, nil, err
	}

	return certs, privateKey, nil
}

type IssuedCertificateStatus string

const (
	ValidIssuedCertificateStatus   IssuedCertificateStatus = "Valid"
	RevokedIssuedCertificateStatus IssuedCertificateStatus = "Revoked"
)

type IssuedCertificateEntry struct {
	CommonName          string                  `bson:"common_name,omitempty"`
	Certificate         string                  `bson:"certificate,omitempty"`
	SerialHex           string                  `bson:"serial_hex,omitempty"`
	Status              IssuedCertificateStatus `bson:"status,omitempty"`
	IssueTimeStamp      string                  `bson:"issue_timestamp,omitempty"`
	RevocationTimeStamp string                  `bson:"revocation_timestamp,omitempty"`
}

func (m MongoDBStorage) Put(name string, crt *x509.Certificate) error {
	if crt == nil {
		return errors.New("crt is nil")
	}
	if crt.Raw == nil {
		return errors.New("data is nil")
	}
	if crt.SerialNumber == nil {
		return errors.New("serial number is nil")
	}

	serialHex := fmt.Sprintf("%X", crt.SerialNumber)
	if len(serialHex)%2 == 1 {
		serialHex = fmt.Sprintf("0%s", serialHex)
	}

	certEntry := IssuedCertificateEntry{
		Certificate: string(pem.EncodeToMemory(&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   crt.Raw,
		})),
		CommonName:     certName(crt),
		SerialHex:      serialHex,
		Status:         ValidIssuedCertificateStatus,
		IssueTimeStamp: strconv.FormatInt(crt.NotBefore.Unix(), 10),
	}

	_, err := m.HasCN(certName(crt), 0, crt, true)
	if err != nil {
		return err
	}

	_, err = m.IssuedCertsCollection.InsertOne(context.TODO(), certEntry)
	if err != nil {
		return err
	}

	return m.incrementSerial(crt.SerialNumber)
}

type SerialNumberEntry struct {
	CurrentMaxSerialHex string `bson:"current_max_serial,omitempty"`
}

func (m MongoDBStorage) incrementSerial(s *big.Int) error {
	serialHex := fmt.Sprintf("%X", s.Add(s, big.NewInt(1)))
	if len(serialHex)%2 == 1 {
		serialHex = fmt.Sprintf("0%s", serialHex)
	}

	upsert := true
	filter := bson.M{}
	update := bson.M{
		"$set": SerialNumberEntry{
			CurrentMaxSerialHex: serialHex,
		},
	}
	_, err := m.SerialNumberCollection.UpdateOne(context.TODO(), filter, update, options.Update().SetUpsert(upsert))

	return err
}

func (m MongoDBStorage) Serial() (*big.Int, error) {
	filter := bson.M{}
	s := big.NewInt(2)

	res := SerialNumberEntry{}
	err := m.SerialNumberCollection.FindOne(context.TODO(), filter).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return s, nil
		}
		return nil, err
	}

	s, ok := s.SetString(res.CurrentMaxSerialHex, 16)
	if !ok {
		return nil, errors.New("could not convert " + res.CurrentMaxSerialHex + " to serial number")
	}

	return s, nil
}

func (m MongoDBStorage) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error) {
	// TODO - implement allowTime

	filter := bson.M{
		"$or": bson.A{
			bson.M{
				"certificate": string(pem.EncodeToMemory(&pem.Block{
					Type:    "CERTIFICATE",
					Headers: nil,
					Bytes:   cert.Raw,
				})),
			},
			bson.M{
				"common_name": utf8Check(cn),
			},
		},
	}
	res := IssuedCertificateEntry{}
	err := m.IssuedCertsCollection.FindOne(context.TODO(), filter).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, nil
		}
		return false, err
	}
	if revokeOldCertificate {
		upsert := true
		update := bson.M{
			"$set": IssuedCertificateEntry{
				Certificate: string(pem.EncodeToMemory(&pem.Block{
					Type:    "CERTIFICATE",
					Headers: nil,
					Bytes:   cert.Raw,
				})),
				Status:              RevokedIssuedCertificateStatus,
				RevocationTimeStamp: strconv.FormatInt(time.Now().Unix(), 10),
			},
		}

		_, err := m.IssuedCertsCollection.UpdateOne(context.TODO(), filter, update, options.Update().SetUpsert(upsert))
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return utf8Check(string(crt.Signature))
}

func utf8Check(input string) string {
	if utf8.Valid([]byte(input)) {
		return input
	}

	return hex.EncodeToString([]byte(input))
}
