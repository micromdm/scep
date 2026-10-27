package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/smallstep/pkcs7"
)

// withOAEPKeyTransport rewraps the content key of a PKCS #1 v1.5 envelope with
// RSAES-OAEP, the key transport NDES uses when it answers in AES-192.
func withOAEPKeyTransport(t *testing.T, der []byte, key *rsa.PrivateKey, hash crypto.Hash, label []byte, params []byte) []byte {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		t.Fatal(err)
	}
	contentKey, err := rsa.DecryptPKCS1v15(nil, key, ed.RecipientInfos[0].EncryptedKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := rsa.EncryptOAEP(hash.New(), rand.Reader, &key.PublicKey, contentKey, label)
	if err != nil {
		t.Fatal(err)
	}
	ed.RecipientInfos[0].EncryptedKey = encryptedKey
	ed.RecipientInfos[0].KeyEncryptionAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm:  pkcs7.OIDEncryptionAlgorithmRSAESOAEP,
		Parameters: asn1.RawValue{FullBytes: params},
	}
	inner, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(contentInfo{
		ContentType: pkcs7.OIDEnvelopedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: inner, IsCompound: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func explicitOAEPParameters(t *testing.T, digest asn1.ObjectIdentifier, mgfDigest asn1.ObjectIdentifier, label []byte) []byte {
	t.Helper()
	return mustMarshal(t, rsaOAEPParameters{
		HashFunc: pkix.AlgorithmIdentifier{Algorithm: digest, Parameters: asn1.NullRawValue},
		MaskGenFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidMGF1,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, pkix.AlgorithmIdentifier{Algorithm: mgfDigest, Parameters: asn1.NullRawValue})},
		},
		PSourceFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidPSpecified,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, label)},
		},
	})
}

func TestDecryptEnvelopeOAEP(t *testing.T) {
	caCert, caKey := newTestCA(t)
	content := []byte("issued certificate in a degenerate PKCS #7")

	for _, tc := range []struct {
		name   string
		hash   crypto.Hash
		label  []byte
		params func(t *testing.T) []byte
	}{
		{"default parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return mustMarshal(t, rsaOAEPParameters{}) }},
		{"absent parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return nil }},
		{"SHA-256 with label", crypto.SHA256, []byte("label"), func(t *testing.T) []byte {
			return explicitOAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA256, []byte("label"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := aesCBCAlgorithms[1].encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}
			der = withOAEPKeyTransport(t, der, caKey, tc.hash, tc.label, tc.params(t))

			got, err := decryptEnvelope(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("decryptEnvelope = %q, want %q", got, content)
			}
		})
	}
}

func TestDecryptEnvelopeOAEPRejectsMismatchedMGF1Hash(t *testing.T) {
	caCert, caKey := newTestCA(t)
	der, err := aesCBCAlgorithms[1].encrypt([]byte("content"), []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	params := explicitOAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA1, nil)
	der = withOAEPKeyTransport(t, der, caKey, crypto.SHA256, nil, params)

	if _, err := decryptEnvelope(der, caCert, caKey); err == nil {
		t.Fatal("expected an error for an MGF1 hash different from the OAEP hash")
	}
}

// TestDecryptEnvelopeOAEPOpenSSL opens AES-192 envelopes whose content key
// openssl wrapped with RSAES-OAEP, as a SCEP server answering in AES-192 does.
func TestDecryptEnvelopeOAEPOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	caCert, caKey := newTestCA(t)
	content := []byte("encrypted by openssl")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	inPath := filepath.Join(dir, "content")
	writePEM(t, certPath, "CERTIFICATE", caCert.Raw)
	if err := os.WriteFile(inPath, content, 0600); err != nil {
		t.Fatal(err)
	}

	for name, keyopts := range map[string][]string{
		"SHA-1":   {"-keyopt", "rsa_padding_mode:oaep"},
		"SHA-256": {"-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"cms", "-encrypt", "-binary", "-aes192", "-in", inPath, "-outform", "DER", "-recip", certPath}, keyopts...)
			der, err := exec.Command("openssl", args...).Output()
			if err != nil {
				t.Fatalf("openssl cms -encrypt: %v", err)
			}

			got, err := decryptEnvelope(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("decryptEnvelope = %q, want %q", got, content)
			}
		})
	}
}
