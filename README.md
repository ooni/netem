# Netem

[![GoDoc](https://pkg.go.dev/badge/github.com/ooni/netem/)](https://pkg.go.dev/github.com/ooni/netem/v3) [![Coverage Status](https://coveralls.io/repos/github/ooni/netem/badge.svg?branch=main)](https://coveralls.io/github/ooni/netem?branch=main) [![Slack](https://slack.openobservatory.org/badge.svg)](https://slack.openobservatory.org/)

Netem allows writing integration tests in Go where networking code
uses [Gvisor](https://gvisor.dev/)-based networking. Netem also
includes primitives to emulate link latency, losses, and internet
censorship (null routing, SNI-based blocking, throttling). Using
netem, one can easily simulate complex integration testing scenarios.

## Install instructions

_We currently support go1.19_.

To add netem as a dependency, run:

```bash
go get -u -v -d github.com/ooni/netem
```

This command will download netem and update your `go.mod` and `go.sum`.

## Running tests

```bash
go test ./...
```

## Usage

Suppose you have this Go code:

```Go
func yourCode(ctx context.Context) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, "www.example.com")
	// ...
}
```

You need to convert this code to use netem:

```Go
func yourCode(ctx context.Context, nn *netem.Net) {
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

Your code will still work as intended, but now you have the
option to replace the `Net` underlying stack with an userspace
TCP/IP network stack. Let us suppose that we want to write
a test case for `yourCode`. We first create a [StartTopology](
https://pkg.go.dev/github.com/ooni/netem#StarTopology):

Let us now write a test case for `yourCode`. We need to create
a network topology and poplate it with servers first:

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

As said, the `clientStack` and `serverStack` are [userspace TCP/IP
stacks](https://pkg.go.dev/github.com/ooni/netem#UNetStack) connected
by a [Router](https://pkg.go.dev/github.com/ooni/netem#Router)
living inside the topology.

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
nn := &netem.Net{
	Stack: clientStack,
}
```

By passing this `nn` to `yourCode`, we can execute
`yourCode` using the two userspace network stacks we
just created above.
