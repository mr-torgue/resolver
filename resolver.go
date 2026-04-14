// Package example is a CoreDNS plugin that prints "example" to stdout on every packet received.
//
// It serves as an example CoreDNS plugin with numerous code comments.
package resolver

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
  	"github.com/domainr/dnsr"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("resolver")

// Example is an example plugin to show how to write a plugin.
type Resolver struct {
	R *dnsr.Resolver
	Next plugin.Handler
}

// New returns a new Resolver.
//func New(r *dnsr.Resolver, next plugin.Handler) Resolver {
//	return Resolver{
//		R: r,
//		Next: next,
//	}
//}

// ServeDNS implements the plugin.Handler interface. This method gets called when example is used
// in a Server.
func (e Resolver) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// This function could be simpler. I.e. just fmt.Println("example") here, but we want to show
	// a slightly more complex example as to make this more interesting.
	// Here we wrap the dns.ResponseWriter in a new ResponseWriter and call the next plugin, when the
	// answer comes back, it will print "example".

	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Info(r.String())
	log.Infof("Nr. questions: %d\n", len(r.Question))
	for i:=0; i<len(r.Question); i++ {
		log.Infof("Qname: %s, Qtype: %d\n", r.Question[i].Name, r.Question[i].Qtype)
		for _, rr := range e.R.Resolve(r.Question[i].Name, "A") {
			log.Info(rr.String())
		}
	}

	// Wrap.
	pw := NewResponsePrinter(w)

	// Export metric with the server label set to the current server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Call next plugin (if any).
	return plugin.NextOrFailure(e.Name(), e.Next, ctx, pw, r)
}

// Name implements the Handler interface.
func (e Resolver) Name() string { return "resolver" }

// ResponsePrinter wrap a dns.ResponseWriter and will write example to standard output when WriteMsg is called.
type ResponsePrinter struct {
	dns.ResponseWriter
}

// NewResponsePrinter returns ResponseWriter.
func NewResponsePrinter(w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{ResponseWriter: w}
}

// WriteMsg calls the underlying ResponseWriter's WriteMsg method and prints "example" to standard output.
func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	log.Info("resolver")
	return r.ResponseWriter.WriteMsg(res)
}
