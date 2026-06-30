package resolver

import (
	"os"
	"strconv"
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
//	resolver {
//	  timeout [TimeString] (default "1s")
//	  hints [Filename]     (default "named.root")
//	  anchor [Filename]    (default "root-anchors.xml")
//	  udpsize: [Uint]      (default 1232)
//	  dnsport: [Uint]      (default 53)
//	  doqport: [Uint]      (default 853)
//	  dotport: [Uint]      (default 8853)
//	  clientType [String]  (default "udp")
//	  nofallback           (default false)
//	  nodnssec             (default false)
//	  notlsverify          (default false)
//	  nocache              (default false)
//	  pqcmode              (default true)
//	}
//
// TODO(mr-torgue): tighter checks
func resolverParse(c *caddy.Controller) (*Resolver, error) {

	var R = new(Resolver)
	// set default values
	var (
		timeout           = "1s"
		hints             = "named.root"
		anchor            = "root-anchors.xml"
		dnsPort    uint16 = 53
		doqPort    uint16 = 853
		dotPort    uint16 = 8853
		clientType        = "udp"
		fallback          = true
		tlsverify         = true
		cache             = true
		pqcmode           = false
	)
	R.DNSSEC = true
	R.udpsize = 1232

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
				if !c.NextArg() {
					return nil, c.Errf("udpsize not provided, format: udpsize \"[UINT]\"")
				}
				tmpsize, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("could not parse unsigned integer %s for udpsize: %s", c.Val(), err)
				}
				R.udpsize = uint16(tmpsize)
			case "dnsport":
				if !c.NextArg() {
					return nil, c.Errf("dnsport not provided, format: dnsport \"[UINT]\"")
				}
				tmpsize, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("could not parse unsigned integer %s for dnsport: %s", c.Val(), err)
				}
				dnsPort = uint16(tmpsize)
			case "doqport":
				if !c.NextArg() {
					return nil, c.Errf("doqport not provided, format: doqport \"[UINT]\"")
				}
				tmpsize, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("could not parse unsigned integer %s for doqport: %s", c.Val(), err)
				}
				doqPort = uint16(tmpsize)
			case "dotport":
				if !c.NextArg() {
					return nil, c.Errf("dotport not provided, format: dotport \"[UINT]\"")
				}
				tmpsize, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("could not parse unsigned integer %s for dotport: %s", c.Val(), err)
				}
				dotPort = uint16(tmpsize)
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
			case "nocache":
				cache = false
			case "pqcmode":
				pqcmode = true
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
	var rslvr *resolver.Resolver
	if cache {
		rslvr = resolver.NewResolver(resolver.ConfigBuilder(
			resolver.WithClient(clientType, fallback),
			resolver.WithCustomRoot(hints, anchor),
			resolver.WithTimeouts(timeoutDuration, timeoutDuration, timeoutDuration, timeoutDuration),
			resolver.WithTLSVerification(tlsverify),
			resolver.WithPQCMode(pqcmode),
			resolver.WithUDPSize(R.udpsize),
			resolver.WithDNSPort(int(dnsPort)),
			resolver.WithDoQPort(int(doqPort)),
			resolver.WithDoTPort(int(dotPort)),
			resolver.WithCache(2000),
		))
	} else {
		rslvr = resolver.NewResolver(resolver.ConfigBuilder(
			resolver.WithClient(clientType, fallback),
			resolver.WithCustomRoot(hints, anchor),
			resolver.WithTimeouts(timeoutDuration, timeoutDuration, timeoutDuration, timeoutDuration),
			resolver.WithTLSVerification(tlsverify),
			resolver.WithPQCMode(pqcmode),
			resolver.WithUDPSize(R.udpsize),
			resolver.WithDNSPort(int(dnsPort)),
			resolver.WithDoQPort(int(doqPort)),
			resolver.WithDoTPort(int(dotPort)),
		))
	}
	// return error if we could not create the resolver
	if rslvr == nil {
		return nil, c.Errf("could not create resolver")
	}
	R.R = rslvr
	return R, nil
}
