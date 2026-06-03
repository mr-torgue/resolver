package resolver

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/stretchr/testify/assert"
)

// TestSetup tests the various things that should be parsed by setup.
// Make sure you also test for parse errors.
func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", `resolver`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}
}

func TestResolverParse(t *testing.T) {

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		//expectedErr			string

	}{
		{
			"should work with most basic setup",
			"resolver",
			false,
		},
		{
			"should fail because of non-existent option",
			`resolver {
				no_reload
			}`,
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", test.input)
			rslvr, err := resolverParse(c)

			if test.shouldErr {
				assert.NotNil(t, err, "expected an error")
				//assert.ErrorContains(t, err, tt.expectedError, "lookup errors should match")
			} else {
				assert.Nil(t, err, "did not expect an error")
				assert.NotNil(t, rslvr, "resolver should not be nil")
			}
		})
	}
}
