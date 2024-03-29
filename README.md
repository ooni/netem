# Netem

[![alltests](https://github.com/ooni/netem/actions/workflows/alltests.yml/badge.svg)](https://github.com/ooni/netem/actions/workflows/alltests.yml) [![GoDoc](https://pkg.go.dev/badge/github.com/ooni/netem/)](https://pkg.go.dev/github.com/ooni/netem) [![Coverage Status](https://coveralls.io/repos/github/ooni/netem/badge.svg?branch=main)](https://coveralls.io/github/ooni/netem?branch=main) [![Slack](https://slack.openobservatory.org/badge.svg)](https://slack.openobservatory.org/)

Netem allows writing integration tests in Go where networking code
uses [Gvisor](https://gvisor.dev/)-based networking. Netem also
includes primitives to emulate link latency, losses, and internet
censorship (null routing, SNI-based blocking, throttling). Using
netem, one can easily simulate complex integration testing scenarios
involving difficult or adversarial networks.

## Install instructions

_We currently support go1.20_.

To add netem as a dependency, run:

```console
go get -u -v -d github.com/ooni/netem
```

This command will download netem and update your `go.mod` and `go.sum`.

You _probably_ also want to manually force using the [Gvisor](https://gvisor.dev/)
version we're using in this library with:

```
go get -u -v -d gvisor.dev/gvisor@COMMIT_HASH
```

because [Gvisor](https://gvisor.dev/)'s default branch is not
ready to be used with Go tools and `go get` would misbehave.

When updating [Gvisor](https://gvisor.dev/) in this library, make sure
you pin to a commit from the [go](https://github.com/google/gvisor/tree/go) branch,
which is the [Gvisor](https://gvisor.dev/) branch supporting go tools.

## Running tests

```console
go test .
```

To enable the race detector, run:

```console
go test -race .
```

*Note*: we notice that the race detector would be very slow under macOS
and many tests will fail; it still seems to be fine under Linux.

## Usage

TODO(bassosimone): this section needs to be updated because we have
recently removed the `stdlib.go` file and functionality, since we have
much better functionality inside of ooni/probe-cli.

Existing Go code needs to be adjusted to support netem.

Suppose you have this Go code:

```Go
func yourCode(ctx context.Context) error {
	addrs, err := net.DefaultResolver.LookupHost(ctx, "www.example.com")
	// ...
}
```

You need to convert this code to use netem:

```Go
func yourCode(ctx context.Context, nn *netem.Net) error {
	addrs, err := nn.LookupHost(ctx, "www.example.com")
	// ...
}
```

Normally, you would create a [netem.Net](
https://pkg.go.dev/github.com/ooni/netem#Net) like this:

```Go
nn := &netem.Net{
	Stack: &netem.Stdlib{},
}
```

Your code will still work as intended. But, now you have the
option to replace the `Net` underlying stack with an userspace
TCP/IP network stack, for writing integration tests.

Let us do that. We start by creating a [StarTopology](
https://pkg.go.dev/github.com/ooni/netem#StarTopology):

```Go
topology, err := netem.NewStarTopology(&netem.NullLogger{})
if err != nil { /* ... */ }

defer topology.Close()
```

Then, we use [AddHost](https://pkg.go.dev/github.com/ooni/netem#StarTopology.AddHost)
to add two userspace network stacks to such a topology:

```Go
clientStack, err := netem.AddHost(
	"1.2.3.4",            // stack IPv4 address
	"5.4.3.2",            // resolver IPv4 address
	&netem.LinkConfig{},  // link with no delay, losses, or DPI
)
if err != nil { /* ... */ }

serverStack, err := netem.AddHost(
	"5.4.3.2",            // stack IPv4 address
	"5.4.3.2",            // resolver IPv4 address
	&netem.LinkConfig{},  // link with no delay, losses, or DPI
)
if err != nil { /* ... */ }
```

We now have the following topology:

```mermaid
graph TD
 client[clientStack<br>1.2.3.4]---router{Router}
 server[serverStack<br>5.4.3.2]---router
```

Now, we can create a [DNSServer](
https://pkg.go.dev/github.com/ooni/netem#DNSServer)
on `5.4.3.2` as follows:

```Go
dnsCfg := netem.NewDNSConfig()
dnsCfg.AddRecord(
	"www.example.com",
	"",                 // empty CNAME
	"5.6.7.8",
)

dnsServer, err := netem.NewDNSServer(
	&netem.NullLogger{},
	serverStack,
	"5.4.3.2",
	dnsCfg,
)
if err != nil { /* ... */ }
```

Finally, we create a [netem.Net](
https://pkg.go.dev/github.com/ooni/netem#Net) as follows:

```Go
nn2 := &netem.Net{
	Stack: clientStack,
}
```

and we can test `yourCode` as follows:

```Go
func TestYourCode(t *testing.T) {
	// ... create nn2 ...
	err := yourCode(context.Background(), nn2)
	if err != nil {
		t.Fatal(err)
	}
}
```

This test will test your code using the above
network stacks and topology.
