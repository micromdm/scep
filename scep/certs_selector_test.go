package scep

import (
	"crypto/x509"
	"testing"
)

func TestEnciphermentCertsSelector(t *testing.T) {
	for _, test := range []struct {
		testName              string
		certs                 []*x509.Certificate
		expectedSelectedCerts []*x509.Certificate
	}{
		{
			"empty certificates list",
			[]*x509.Certificate{},
			[]*x509.Certificate{},
		},
		{
			"non-empty certificates list",
			[]*x509.Certificate{
				{KeyUsage: x509.KeyUsageKeyEncipherment},
				{KeyUsage: x509.KeyUsageDataEncipherment},
				{KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment},
				{KeyUsage: x509.KeyUsageDigitalSignature},
				{},
			},
			[]*x509.Certificate{
				{KeyUsage: x509.KeyUsageKeyEncipherment},
				{KeyUsage: x509.KeyUsageDataEncipherment},
				{KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment},
			},
		},
	} {
		test := test
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			selected := EnciphermentCertsSelector{}.SelectCerts(test.certs)
			if !certsKeyUsagesEq(selected, test.expectedSelectedCerts) {
				t.Fatal("selected and expected certificates did not match")
			}
		})
	}
}

func TestNopCertsSelector(t *testing.T) {
	for _, test := range []struct {
		testName              string
		certs                 []*x509.Certificate
		expectedSelectedCerts []*x509.Certificate
	}{
		{
			"empty certificates list",
			[]*x509.Certificate{},
			[]*x509.Certificate{},
		},
		{
			"non-empty certificates list",
			[]*x509.Certificate{
				{KeyUsage: x509.KeyUsageKeyEncipherment},
				{KeyUsage: x509.KeyUsageDataEncipherment},
				{KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment},
				{KeyUsage: x509.KeyUsageDigitalSignature},
				{},
			},
			[]*x509.Certificate{
				{KeyUsage: x509.KeyUsageKeyEncipherment},
				{KeyUsage: x509.KeyUsageDataEncipherment},
				{KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment},
				{KeyUsage: x509.KeyUsageDigitalSignature},
				{},
			},
		},
	} {
		test := test
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			selected := NopCertsSelector{}.SelectCerts(test.certs)
			if !certsKeyUsagesEq(selected, test.expectedSelectedCerts) {
				t.Fatal("selected and expected certificates did not match")
			}
		})
	}
}

// certsKeyUsagesEq returns true if certs in a have the same key usages
// of certs in b and in the same order.
func certsKeyUsagesEq(a []*x509.Certificate, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i, cert := range a {
		if cert.KeyUsage != b[i].KeyUsage {
			return false
		}
	}
	return true
}
