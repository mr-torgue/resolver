package resolver

import (
	"time"
	"os"
	"strings"
	"strconv"
	"slices"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
  	"github.com/mr-torgue/dnsr"
)

// init registers this plugin.
func init() { plugin.Register("resolver", setup) }

// setup is the function that gets called when the config parser see the token "resolver".
// TODO(mr-torgue): stricter checks
func setup(c *caddy.Controller) error {
	// parse configuration
	rslvr, err := resolverParse(c)
	if err != nil {
		return plugin.Error("resolver", err)
	}
	// r := dnsr.NewResolver(dnsr.WithExpire(true))
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Resolver { R: rslvr, Next: next }
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
// resolver {
//    timeout [TimeString]
//    clientTimeout [TimeString]
//    hints [Filename]
//    anchor [Filename]
//    edns [Bool]
//    udpsize: [Uint]
//    dnssecValidation [Bool]
//    clientType [String]
// } 
// TODO(mr-torgue): tighter checks
func resolverParse(c *caddy.Controller) (*dnsr.Resolver, error) {

	// set default values
	var (
		timeout = "10s"
		clientTimeout = "2s"
		hints = "named.root"
		//anchor = "anchor.root"
		edns = false
		udpsize uint16 = 1232
		dnssec = false
		clientType = "udp"
	) 

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
			case "clientTimeout":
				if !c.NextArg() {
					return nil, c.Errf("clientTimeout not provided, format: clientTimeout \"[TIMESTRING]\"")
				}
				clientTimeout = c.Val()
				if !isTimeString(clientTimeout) {
					return nil, c.Errf("invalid duration: %s", clientTimeout)
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
				// TODO(mr-torgue): check if file exists and is in right format
				// TODO(mr-torgue): not-implemented
				return nil, c.Errf("anchor has not been implemented yet!")
			case "edns":
				if c.NextArg() {
					edns = strings.ToLower(c.Val()) == "false"
				}
			case "udpsize":
				if !c.NextArg() {
					return nil, c.Errf("udpsize not provided, format: udpsize \"[UINT]\"")
				}
				tmpsize, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("could not parse unsigned integer %s for udpsize: %s", c.Val(), err)
				}
				udpsize = uint16(tmpsize)
			case "dnssecValidation":
				if c.NextArg() {
					dnssec = strings.ToLower(c.Val()) == "false"
				}
			case "clientType":
				if !c.NextArg() {
					return nil, c.Errf("udpsize not provided, format: udpsize \"[UINT]\"")
				}
				clientType = c.Val()
				if !slices.Contains([]string{"udp", "tcp", "dot", "doq", "doh"}, clientType) {
					return nil, c.Errf("client type only supports udp, tcp, dot, doq, or doh")
				}
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}			
		}
	}

	if dnssec && !edns {
		return nil, c.Errf("edns needs to be enabled for dnssec")
	}

	rslvr := dnsr.NewResolver(
		dnsr.WithTimeout(timeout),
		dnsr.WithClientTimeout(clientTimeout),
		dnsr.WithRootfile(hints),
		dnsr.WithEDNS(edns),
		dnsr.WithUDPSize(udpsize),
		dnsr.WithDNSSEC(dnssec),
		dnsr.WithClientType(clientType),
	)
	// return error if we could not create the resolver
	if rslvr == nil {
		return nil, c.Errf("could not create resolver")
	}
	return rslvr, nil
}