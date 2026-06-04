package resolver

import (
	"os"
	"time"

	"github.com/coredns/caddy"
	"github.com/mr-torgue/coredns/core/dnsserver"
	"github.com/mr-torgue/coredns/plugin"
	"github.com/mr-torgue/resolver-lib"
)

// init registers this plugin.
func init() { plugin.Register("resolver", setup) }

// setup is the function that gets called when the config parser see the token "resolver".
// TODO(mr-torgue): stricter checks
func setup(c *caddy.Controller) error {
	// parse configuration
	R, err := resolverParse(c)
	if err != nil {
		return plugin.Error("resolver", err)
	}
	// r := dnsr.NewResolver(dnsr.WithExpire(true))
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		R.Next = next
		return R
	})

	// All OK, return a nil error.
	return nil
}

func isTimeString(s string) bool {
	_, err := time.ParseDuration(s)
	return err == nil
}

func fileExists(s string) bool {
	_, err := os.Stat(s)
	return err == nil
}

// resolveParse parses the config file. Format:
//
//			resolver {
//			   timeout [TimeString]
//			   hints [Filename]
//			   anchor [Filename]
//			   udpsize: [Uint]
//			   clientType [String]
//		       nofallback
//	        nodnssec
//	        notlsverify
//			}
//
// TODO(mr-torgue): tighter checks
func resolverParse(c *caddy.Controller) (*Resolver, error) {

	var R = new(Resolver)
	// set default values
	var (
		timeout = "1s"
		hints   = "named.root"
		anchor  = "root-anchors.xml"
		//udpsize    uint16 = 1232
		clientType = "udp"
		fallback   = true
		tlsverify  = true
	)
	R.DNSSEC = true

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "timeout":
				if !c.NextArg() {
					return nil, c.Errf("timeout not provided, format: timeout \"[TIMESTRING]\"")
				}
				timeout = c.Val()
				if !isTimeString(timeout) {
					return nil, c.Errf("invalid duration: %s", timeout)
				}
			case "hints":
				if !c.NextArg() {
					return nil, c.Errf("hints file not provided, format: hints \"[FILENAME]\"")
				}
				hints = c.Val()
				if !fileExists(hints) {
					return nil, c.Errf("file %s does not exist", hints)
				}
			case "anchor":
				if !c.NextArg() {
					return nil, c.Errf("anchor file not provided, format: anchor \"[FILENAME]\"")
				}
				anchor = c.Val()
				if !fileExists(anchor) {
					return nil, c.Errf("file %s does not exist", anchor)
				}
			case "udpsize":
				//if !c.NextArg() {
			//		return nil, c.Errf("udpsize not provided, format: udpsize \"[UINT]\"")
			//}
			//tmpsize, err := strconv.ParseUint(c.Val(), 10, 16)
			//if err != nil {
			//	return nil, c.Errf("could not parse unsigned integer %s for udpsize: %s", c.Val(), err)
			//}
			//udpsize = uint16(tmpsize)
			case "clientType":
				if !c.NextArg() {
					return nil, c.Errf("client type not provided, format: clientType \"[TYPE]\"")
				}
				clientType = c.Val()
				allowedTypes := []string{"udp", "tcp", "dot", "doq"}
				found := false
				for _, t := range allowedTypes {
					if t == clientType {
						found = true
						break
					}
				}
				if !found {
					return nil, c.Errf("client type only supports udp, tcp, dot, or doq")
				}
			case "nofallback":
				fallback = false
			case "nodnssec":
				R.DNSSEC = false
			case "notlsverify":
				tlsverify = false
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}
	timeoutDuration, err := time.ParseDuration(timeout)
	if err != nil {
		return nil, c.Errf("invalid duration: %s", timeout)
	}
	// use the same timeout for all clients, not great but should work
	rslvr := resolver.NewResolver(resolver.ConfigBuilder(resolver.WithClient(clientType, fallback), resolver.WithCustomRoot(hints, anchor), resolver.WithTimeouts(timeoutDuration, timeoutDuration, timeoutDuration, timeoutDuration), resolver.WithTLSVerification(tlsverify)))
	// return error if we could not create the resolver
	if rslvr == nil {
		return nil, c.Errf("could not create resolver")
	}
	R.R = rslvr
	return R, nil
}
