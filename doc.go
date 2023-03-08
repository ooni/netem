// Package netem is a framework to write integration tests that
// use TCP/IP stacks implemented in userspace.
//
// Assuming that your code depends on [UnderlyingNetwork] (or
// on its wrapper [Net]), you can write your tests to create
// and use Gvisor-based TCP/IP stacks in userspace. To this end, use the
// [NewUNetStack] constructor or create it in the context
// of a specific network topology (explained below). Because
// [UNetStack] implements the [UnderlyingNetwork] model, your
// code can now use the TCP/IP stack in userspace as opposed
// to the Go standard library.
//
// For normal operations, instead, you can use the [Stdlib]
// struct. This struct implements [UnderlyingNetwork]
// using the Go standard library. So, when your code uses
// a [Stdlib] as its [UnderlyingNetwork], it will use your
// host network as usual.
//
// A [UNetStack] alone is not attached to any link and so
// it cannot communicate with any other host. To connect
// two [UNetStack], use [NewLink]. This factory will create
// a [Link], which implements the following:
//
// - delivery of TCP/IP packets between the two [UNetStack];
//
// - optionally, emulation of packet loss rate, addition
// of extra round trip time, and presence of DPI rules.
//
// You configure the link properties using [LinkConfig], which
// is the structure you pass to [NewLink].
//
// Rather than using a [Link] to connect two [UNetStack]
// in point-to-point fashion, you can alternatively create
// a [Router]. A new [Router] is not attached to any
// other host and so is not routing. To attach a [UNetStack]
// to a router, create a [RouterPort] and a [Link] between
// such a [UNetStack] and the [RouterPort]. Using the [Router]
// you can create complex topologies.
//
// Because creating topologies manually is error
// prone, we have two predefined topologies:
//
// - the [PPPTopology] automates creating a [Link] between two
// [UNetStack] instances;
//
// - the [StarTopology] automates creating a [Router] and
// links between [UNetStack] and [RouterPort].
//
// The [UnderlyingNetwork] model includes a method to obtain the
// root X.509 certificate pool to use. When you are using a
// [UNetStack], the root X.509 is constructed such that we are
// able to automatically produce a certificate for any SNI on
// the server side as long as the client code uses such a root.
package netem
