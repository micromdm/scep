package scep

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestCaddySetup(t *testing.T) {
	input := `scep {
        depot ../scep/testdata/testca
        # keepass secret
        # challenge sharedsecret
    }`
	c := caddy.NewTestController(input)
	err := setup(c)
	if err != nil {
		t.Fatal(err)
	}
}
