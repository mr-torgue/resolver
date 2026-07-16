// Package example is a CoreDNS plugin that prints "example" to stdout on every packet received.
//
// It serves as an example CoreDNS plugin with numerous code comments.
package resolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/mr-torgue/coredns/plugin"
	//"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/mr-torgue/coredns/plugin/pkg/log"

	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("resolver")

// Example is an example plugin to show how to write a plugin.
type Resolver struct {
	R       *resolver.Resolver
	Next    plugin.Handler
	DNSSEC  bool
	udpsize uint16
}

// ServeDNS implements the plugin.Handler interface. This method gets called when example is used
// in a Server.
func (e Resolver) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	log.Debugf("Received query: %s\n", r.String())

	// not incredibly efficient, but needed because we might make some changes to the query
	qmsg := r.Copy()

	removeDNSSEC := false
	edns0 := qmsg.IsEdns0()
	if !e.DNSSEC && edns0 != nil { // DNSSEC disabled but EDNS not nil --> make sure to remove DO flag
		edns0.SetDo(false)
	}
	if e.DNSSEC {
		if edns0 == nil { // no EDNS --> remove DNSSEC records but do verify
			qmsg.SetEdns0(e.udpsize, true)
			removeDNSSEC = true
		} else if !edns0.Do() { // EDNS provided but Do is set to false --> remove DNSSEC records but do verify
			edns0.SetDo(true)
			removeDNSSEC = true
		}
	}

	rsp := e.R.Exchange(context.Background(), qmsg)
	if rsp == nil {
		return dns.RcodeServerFailure, errors.New("resolver failed: no response received")
	}
	if rsp.Err != nil {
		return dns.RcodeServerFailure, fmt.Errorf("resolver failed: %w", rsp.Err)
	}
	rmsg := rsp.Msg
	if rmsg == nil {
		return dns.RcodeServerFailure, errors.New("resolver failed: no message in response")
	}
	rmsg.Id = qmsg.Id // in case QUIC or TLS is used

	// remove DNSSEC related data from the response if do bit was not set
	if removeDNSSEC {
		// Helper to filter a slice in-place
		filterDNS := func(slice []dns.RR) []dns.RR {
			n := 0
			for _, rr := range slice {
				header := rr.Header()
				// Check if we should KEEP this record
				if header.Rrtype != dns.TypeRRSIG &&
					header.Rrtype != dns.TypeNSEC &&
					header.Rrtype != dns.TypeDS &&
					header.Rrtype != dns.TypeDNSKEY {
					slice[n] = rr
					n++
				}
			}
			return slice[:n]
		}

		// Apply to each section
		rmsg.Answer = filterDNS(rmsg.Answer)
		rmsg.Ns = filterDNS(rmsg.Ns)
		rmsg.Extra = filterDNS(rmsg.Extra)

		// restored edns0 if existed
		if edns0 != nil {
			rmsg.IsEdns0().SetDo(edns0.Do())
		} else {
			// remove OPT record (copied from popEdns0)
			for i := len(rmsg.Extra) - 1; i >= 0; i-- {
				if rmsg.Extra[i].Header().Rrtype == dns.TypeOPT {
					rmsg.Extra = append(rmsg.Extra[:i], rmsg.Extra[i+1:]...)
				}
			}
		}
	}

	// fix issue where TC flag is set incorrectly
	if rmsg.Len() <= int(e.udpsize) {
		rmsg.Truncated = false
	}

	log.Debugf("Found response for query %s %s\n", rmsg.Question[0].Name, dns.TypeToString[rmsg.Question[0].Qtype])

	w.WriteMsg(rmsg)
	return rmsg.Rcode, nil
}

// Name implements the Handler interface.
func (e Resolver) Name() string { return "resolver" }
