package netem

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// settledGoroutines returns the number of goroutines once it stops decreasing.
func settledGoroutines() int {
	n := runtime.NumGoroutine()
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		m := runtime.NumGoroutine()
		if m >= n {
			return m
		}
		n = m
	}
	return n
}

// Closing a topology must release the GVisor stacks of its hosts: before, each
// closed stack left its protocol workers and timers running forever.
func TestGVisorStackCloseReleasesGoroutines(t *testing.T) {
	before := settledGoroutines()
	for range 5 {
		topology := MustNewStarTopology(&NullLogger{})
		client := Must1(topology.AddHost("10.0.0.1", "10.0.0.1", &LinkConfig{}))
		server := Must1(topology.AddHost("10.0.0.2", "10.0.0.1", &LinkConfig{}))

		// exchange some bytes over TCP, so that the stacks have endpoints and timers
		ln := Must1(server.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 80}))
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := client.DialContext(ctx, "tcp", "10.0.0.2:80")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(conn)
		if err != nil || string(data) != "hello" {
			t.Fatalf("read %q: %v", data, err)
		}
		_ = conn.Close()
		_ = ln.Close()

		Must0(topology.Close())
	}
	if after := settledGoroutines(); after > before+2 {
		t.Fatalf("goroutines: %d before, %d after closing 5 topologies", before, after)
	}
}

// After Close, a stack refuses new connections instead of hanging or panicking.
func TestGVisorStackUnusableAfterClose(t *testing.T) {
	topology := MustNewStarTopology(&NullLogger{})
	client := Must1(topology.AddHost("10.0.0.1", "10.0.0.1", &LinkConfig{}))
	Must1(topology.AddHost("10.0.0.2", "10.0.0.1", &LinkConfig{}))
	Must0(topology.Close())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := client.DialContext(ctx, "tcp", "10.0.0.2:80"); err == nil {
		_ = conn.Close()
		t.Fatal("dial succeeded on a closed stack")
	}
}
