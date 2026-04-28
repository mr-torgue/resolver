package resolver

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
  	"github.com/mr-torgue/dnsr"
)

// init registers this plugin.
func init() { plugin.Register("resolver", setup) }

// setup is the function that gets called when the config parser see the token "example". Setup is responsible
// for parsing any extra options the example plugin may have. The first token this function sees is "example".
func setup(c *caddy.Controller) error {
	c.Next() // Ignore "example" and give us the next token.
	if c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error("resolver", c.ArgErr())
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	//r := dnsr.NewResolver(dnsr.WithExpiry())
	//r := New()


	//c.OnStartup(func() error {
	//	ca.viewMetricLabel = dnsserver.GetConfig(c).ViewName
	//	return nil
	//})
	r := dnsr.NewResolver(dnsr.WithExpire(true))
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Resolver {R: r, Next: next}
	})

	// All OK, return a nil error.
	return nil
}
