# resolver

## Name

*resolver* - fully iterative DNSSEC-enabled resolver based on [resolver-lib](https://github.com/mr-torgue/resolver-lib) with support for post quantum cryptography.

## Description

CoreDNS supported resolving trough bthe forward plugin but did not have a dedicated iterative resolver.
This resolver plugin adds that functionality.
It supports:
1. DNSSEC
2. PQC algorithms
It does not have a cache, which we will leave for future releases.

## Compilation

This package will always be compiled as part of CoreDNS and not in a standalone way. It will require you to use `go get` or as a dependency on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg).

The [manual](https://coredns.io/manual/toc/#what-is-coredns) will have more information about how to configure and extend the server with external plugins.

A simple way to consume this plugin, is by adding the following on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg), and recompile it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

~~~
example:github.com/coredns/example
~~~

Put this early in the plugin list, so that *example* is executed before any of the other plugins.

After this you can compile coredns by:

``` sh
go generate
go build
```

Or you can instead use make:

``` sh
make
```

## Syntax
The following options are supported:
~~~ txt
resolver {
	timeout [TimeString] (default "1s")
	hints [Filename]     (default "named.root")
	anchor [Filename]    (default "root-anchors.xml")
	udpsize: [Uint]      (default 1232)
    dnsport: [Uint]      (default 53)
    doqport: [Uint]      (default 853)
	dotport: [Uint]      (default 8853)
    clientType [String]  (default "udp")
	nofallback          
	nodnssec            
	notlsverify          
	nocache     
	notlscache         
	nopqcmode             
}
~~~

## Metrics

TBD

## Ready

This plugin reports readiness to the ready plugin. It will be immediately ready.

## Examples

TBD

## Also See

See the [manual](https://coredns.io/manual).
