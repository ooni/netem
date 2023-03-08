# Network emulation for writing integration tests in Go

Netem allows writing integration tests where networking Go code is attached
to a [Gvisor](https://gvisor.dev/)-based userspace TCP/IP stack and
communicates with servers written in Go and running in other userspace
network stacks. Netem provides primities allowing one to connect
those network stacks together through links and routers. Links optionally
have round-trip time and packet loss rate constraints. You can also
configure DPI rules to selectively drop packets, inject RST segments
or throttle flows. Routers allow you to connect multiple TCP/IP
stacks together and form more complex topologies.

## Install instructions

_We currently support go1.18 and go1.19_.

To add netem as a dependency, run:

```bash
go get -u -v -d github.com/ooni/netem
```

This command will download netem and update your `go.mod`
and `go.sum` files such that netem is a dependency.

## Running tests

```bash
go test ./...
```
