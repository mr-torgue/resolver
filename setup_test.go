package resolver

import (
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/coredns/caddy"
	"github.com/mr-torgue/resolver-lib"
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
		expectedPQCMode    bool
		expectedCache      bool
		expectedUDPSize    uint16
		//expectedErr			string

	}{
		{
			name:            "should work with most basic setup",
			input:           "resolver",
			shouldErr:       false,
			expectedDNSSEC:  true,
			expectedPQCMode: false,
			expectedCache:   true,
			expectedUDPSize: 1232,
		},
		{
			name: "should fail because of non-existent option",
			input: `resolver {
				no_reload
			}`,
			expectedUDPSize: 1232,
			expectedCache:   true,
			shouldErr:       true,
		},
		{
			name: "should with complex settings",
			input: `resolver {
				udpsize 1300
				nodnssec
			}`,
			expectedUDPSize: 1300,
			shouldErr:       false,
			expectedCache:   true,
			expectedDNSSEC:  false,
		},
		{
			name: "should disable cache",
			input: `resolver {
				udpsize 1300
				notlscache
				nocache
			}`,
			expectedUDPSize: 1300,
			shouldErr:       false,
			expectedCache:   false,
			expectedDNSSEC:  true,
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
				assert.Equal(t, test.expectedUDPSize, rslvr.udpsize)
				// CAREFUL: MIGHT BREAK!
				v := reflect.ValueOf(rslvr.R).Elem()
				configField := v.FieldByName("config")
				configPtr := *(*(*resolver.Config))(unsafe.Pointer(configField.UnsafeAddr()))
				cv := reflect.ValueOf(configPtr).Elem()
				tlsCache := cv.FieldByName("tlsCache")
				dnsCache := cv.FieldByName("cache")
				assert.True(t, tlsCache.IsValid())
				if test.expectedCache {
					assert.False(t, tlsCache.IsNil())
					assert.False(t, dnsCache.IsNil())
				} else {
					assert.True(t, tlsCache.IsNil())
					assert.True(t, dnsCache.IsNil())
				}
			}
		})
	}
}
