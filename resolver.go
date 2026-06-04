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
	R      *resolver.Resolver
	Next   plugin.Handler
	DNSSEC bool
}

// ServeDNS implements the plugin.Handler interface. This method gets called when example is used
// in a Server.
func (e Resolver) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	log.Debugf("Received query: %s\n", r.String())

	if !e.DNSSEC {
		r.SetEdns0(4096, false)
	}

	rsp := e.R.Exchange(context.Background(), r)
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

	log.Infof("Found response: %s\n", rmsg.String())
	w.WriteMsg(rmsg)
	return rmsg.Rcode, nil
}

// Name implements the Handler interface.
func (e Resolver) Name() string { return "resolver" }
