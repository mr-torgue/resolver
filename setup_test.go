package resolver

import (
	"testing"
	"time"

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
		name               string
		input              string
		shouldErr          bool
		expectedDNSSEC     bool
		expectedTimeout    time.Duration
		expectedHints      string
		expectedAnchor     string
		expectedClientType string
		expectedFallback   bool
		expectedTLSVerify  bool
		//expectedErr			string

	}{
		{
			name:           "should work with most basic setup",
			input:          "resolver",
			shouldErr:      false,
			expectedDNSSEC: true,
		},
		{
			name: "should fail because of non-existent option",
			input: `resolver {
				no_reload
			}`,
			shouldErr: true,
		},
		{
			name: "should with complex settings",
			input: `resolver {
				nodnssec
			}`,
			shouldErr:      false,
			expectedDNSSEC: false,
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
				assert.Equal(t, test.expectedDNSSEC, rslvr.DNSSEC)
			}
		})
	}
}
