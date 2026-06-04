package resolver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/mr-torgue/coredns/plugin/pkg/dnstest"
	"github.com/mr-torgue/coredns/plugin/test"
	"github.com/mr-torgue/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ExpectedRR struct {
	qtype uint16
	value string
}

type TestCase struct {
	name              string
	qname             string
	qtype             uint16
	rcode             int
	expectedNrAnswers int
	expectedAnswers   []ExpectedRR
	expectedNrAuth    int
	expectedAuth      []ExpectedRR
	expectedNrExtra   int
	expectedExtra     []ExpectedRR
}

type TestCaseConfig struct {
	name      string
	config    string
	shouldErr bool
	testCases []TestCase
}

// match returns true if rr is in the expectedRRs slice
func match(rr dns.RR, expectedRRs []ExpectedRR) (bool, int) {
	for i, expectedRR := range expectedRRs {
		if expectedRR.qtype == rr.Header().Rrtype && strings.Contains(rr.String(), expectedRR.value) {
			return true, i
		}
	}
	return false, 0
}

// matchall returns true iff rrs and expectedRRs are the same
func matchall(rrs []dns.RR, expectedRRs []ExpectedRR) bool {
	matchedIndices := make(map[int]bool)
	for _, rr := range rrs {
		matched, index := match(rr, expectedRRs)
		if matched {
			if matchedIndices[index] {
				return false
			}
			matchedIndices[index] = true
		}
	}
	return len(matchedIndices) == len(expectedRRs)
}

func TestResolver(t *testing.T) {

	ctx := context.TODO()
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	tests := []TestCaseConfig{
		{
			name: "UDP resolver without EDNS",
			config: `resolver {
				timeout "5s"
				clientType "udp"
			}
			`,
			shouldErr: false,
			testCases: []TestCase{
				{
					name:              "[UDP] Client should return A record of folmer.info",
					qname:             "folmer.info",
					qtype:             dns.TypeA,
					rcode:             dns.RcodeSuccess,
					expectedNrAnswers: 1,
					expectedAnswers: []ExpectedRR{
						{dns.TypeA, "65.109.0.142"},
					},
					expectedNrAuth: 0,
					expectedAuth:   []ExpectedRR{},
					//expectedNrExtra: 1,
					//expectedExtra: []ExpectedRR {
					//	{dns.TypeOPT, "",},
					//},

				},
				{
					name:              "[UDP] Client should return A record and CNAME record of www.github.com",
					qname:             "www.github.com",
					qtype:             dns.TypeA,
					rcode:             dns.RcodeSuccess,
					expectedNrAnswers: 2,
					expectedAnswers: []ExpectedRR{
						{dns.TypeA, "4.237.22.38"},
						{dns.TypeCNAME, "github.com."},
					},
					expectedNrAuth: 0,
					expectedAuth:   []ExpectedRR{},
				},
				{
					name:              "[UDP] Client should return TXT records and CNAME record of www.github.com",
					qname:             "www.github.com",
					qtype:             dns.TypeTXT,
					rcode:             dns.RcodeSuccess,
					expectedNrAnswers: 21,
					expectedAnswers: []ExpectedRR{
						{dns.TypeTXT, "stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f"},
						{dns.TypeTXT, "docusign=087098e3-3d46-47b7-9b4e-8a23028154cd"},
						{dns.TypeTXT, "TAILSCALE-xOzoDvFUzZr5YYVCQFuD"},
						{dns.TypeTXT, "krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE"},
						{dns.TypeTXT, "adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b"},
						{dns.TypeTXT, "shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o"},
						{dns.TypeTXT, "loom-site-verification=f3787154f1154b7880e720a511ea664d"},
						{dns.TypeTXT, "atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8"},
						{dns.TypeTXT, "facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50"},
						{dns.TypeTXT, "jamf-site-verification=XtaPNIYghF_e_xRDI8CjgQ"},
						{dns.TypeTXT, "google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks"},
						{dns.TypeTXT, "00Dd0000000hHE0=1TBKg000000TN2r"},
						{dns.TypeTXT, "MS=ms58704441"},
						{dns.TypeTXT, "miro-verification=d2e174fdb00c71e0bcf58f8e58c3da2dd80dcfa9"},
						{dns.TypeTXT, "apple-domain-verification=RyQhdzTl6Z6x8ZP4"},
						{dns.TypeTXT, "calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP"},
						{dns.TypeTXT, "MS=ms44452932"},
						{dns.TypeTXT, "google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o"},
						{dns.TypeTXT, "MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805"},
						{dns.TypeTXT, "v=spf1"},
						{dns.TypeCNAME, "github.com."},
					},
					expectedNrAuth: 0,
					expectedAuth:   []ExpectedRR{},
				},
				{
					name:              "[UDP] Client should return NXDOMAIN",
					qname:             "1.com",
					qtype:             dns.TypeA,
					rcode:             dns.RcodeNameError,
					expectedNrAnswers: 0,
					expectedAnswers:   []ExpectedRR{},
					expectedNrAuth:    0,
					expectedAuth:      []ExpectedRR{},
				},
				{
					name:              "[UDP] Test out-of-bailiwick",
					qname:             "pnnl.gov",
					qtype:             dns.TypeA,
					rcode:             dns.RcodeSuccess,
					expectedNrAnswers: 1,
					expectedAnswers: []ExpectedRR{
						{dns.TypeA, "192.101.105.198"},
					},
					expectedNrAuth: 0,
					expectedAuth:   []ExpectedRR{},
				},
				{
					name:              "[UDP] Client should return TXT",
					qname:             "folmer.info",
					qtype:             dns.TypeTXT,
					rcode:             dns.RcodeSuccess,
					expectedNrAnswers: 2,
					expectedAnswers: []ExpectedRR{
						{dns.TypeTXT, "v=spf1"},
						{dns.TypeTXT, "protonmail-verification=9fcd905c800df450c63a61d5585f0ad3439bc0f5"},
					},
					expectedNrAuth: 0,
					expectedAuth:   []ExpectedRR{},
				}, /*
					{
						name: "[UDP] Client should truncate but still work",
						qname: "cisco.com",
						qtype: dns.TypeTXT,
						rcode: dns.RcodeSuccess,
						expectedNrAnswers: 85,
						expectedAnswers: []ExpectedRR {}, // skip this check
						expectedNrAuth: 0,
						expectedAuth: []ExpectedRR {},
					},*/
				// test truncated
				// test with dnssec
				// test with dnss
			},
		},
		{
			name: "UDP resolver with timeout issues",
			config: ` resolver {
				timeout "1ms"
				clientType "udp"
			}
			`,
			shouldErr: false,
			testCases: []TestCase{
				{
					name:              "[UDP] Client should timeout",
					qname:             "folmer.info",
					qtype:             dns.TypeA,
					rcode:             dns.RcodeServerFailure,
					expectedNrAnswers: 0,
					expectedAnswers:   []ExpectedRR{},
					expectedNrAuth:    0,
					expectedAuth:      []ExpectedRR{},
				},
			},
		},
	}

	// loop over client configurations
	for _, ttconfig := range tests {

		// setup Resolver using resolverParse
		c := caddy.NewTestController("dns", ttconfig.config)
		rslvr, err := resolverParse(c)
		x := Resolver{R: rslvr, Next: test.ErrorHandler()}
		assert.Nil(t, err, "expected an error")
		var (
			qmsg dns.Msg
		)

		for _, tt := range ttconfig.testCases {
			t.Run(tt.name, func(t *testing.T) {

				qmsg.SetQuestion(dns.Fqdn(tt.qname), tt.qtype)
				rcode, _ := x.ServeDNS(ctx, rec, &qmsg)
				rmsg := rec.Msg
				fmt.Printf("rmsg: %s\n", rmsg.String())

				require.NotNil(t, rmsg, "response should not be nil")
				assert.Equal(t, tt.rcode, rcode, "rcodes should match")
				assert.Equal(t, tt.expectedNrAnswers, len(rmsg.Answer), "expected a different number of results")
				if len(tt.expectedAnswers) > 0 {
					assert.True(t, matchall(rmsg.Answer, tt.expectedAnswers), "matchall for answers failed")
				}
				if len(tt.expectedAuth) > 0 {
					assert.True(t, matchall(rmsg.Ns, tt.expectedAuth), "matchall for authoritative failed")
				}
				if len(tt.expectedExtra) > 0 {
					assert.True(t, matchall(rmsg.Extra, tt.expectedExtra), "matchall for additional failed")
				}
			})
		}
	}
}
