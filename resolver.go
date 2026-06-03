// Package example is a CoreDNS plugin that prints "example" to stdout on every packet received.
//
// It serves as an example CoreDNS plugin with numerous code comments.
package resolver

import (
	"context"
	"errors"
	"unsafe"

	"github.com/coredns/coredns/plugin"
	//"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
	mydns "github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("resolver")

// Example is an example plugin to show how to write a plugin.
type Resolver struct {
	R    *resolver.Resolver
	Next plugin.Handler
}

// ServeDNS implements the plugin.Handler interface. This method gets called when example is used
// in a Server.
func (e Resolver) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	log.Debugf("Received query: %s\n", r.String())
	myr := (*mydns.Msg)(unsafe.Pointer(r))
	rsp := e.R.Exchange(context.Background(), myr)
	if rsp != nil {
		rmsg := (*dns.Msg)(unsafe.Pointer(rsp.Msg))
		if rmsg != nil {
			log.Infof("Found response: %s\n", rmsg.String())
			w.WriteMsg(rmsg)
			return rmsg.Rcode, nil
		}
	}

	// TODO(mr-torgue): add statistics
	return dns.RcodeServerFailure, errors.New("resolver failed") // don't try next plugin, this is the end
}

// Name implements the Handler interface.
func (e Resolver) Name() string { return "resolver" }
