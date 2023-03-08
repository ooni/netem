package netem

import (
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestLinkFwdWithDelay(t *testing.T) {

	// testcase describes a test case for [LinkFwdWithDelay]
	type testcase struct {
		// name is the name of this test case
		name string

		// delay is the one-way delay to use for forwarding frames.
		delay time.Duration

		// contains the list of frames that we should emit
		emit []*Frame

		// expect contains the list of frames we expect
		expect []*Frame

		// expectRuntimeAtLeast is the minimum runtime we expect
		// to see when running this test case
		expectRuntimeAtLeast time.Duration
	}

	var testcases = []testcase{{
		name:                 "when we send no frame",
		delay:                0,
		emit:                 []*Frame{},
		expect:               []*Frame{},
		expectRuntimeAtLeast: 0,
	}, {
		name:  "when we send some frames",
		delay: time.Second,
		emit: []*Frame{{
			Deadline: time.Time{},
			Flags:    0,
			Payload:  []byte("abcdef"),
		}, {
			Deadline: time.Time{},
			Flags:    0,
			Payload:  []byte("ghi"),
		}},
		expect: []*Frame{{
			Deadline: time.Time{},
			Flags:    0,
			Payload:  []byte("abcdef"),
		}, {
			Deadline: time.Time{},
			Flags:    0,
			Payload:  []byte("ghi"),
		}},
		expectRuntimeAtLeast: time.Second,
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// create the NIC from which to read
			reader := NewStaticReadableNIC("eth0", tc.emit...)

			// create a NIC that will collect frames
			writer := NewStaticWriteableNIC("eth1")

			// create the link configuration
			cfg := &LinkFwdConfig{
				DPIEngine:   nil,
				Logger:      &NullLogger{},
				OneWayDelay: tc.delay,
				PLR:         0,
				Reader:      reader,
				Writer:      writer,
				Wg:          &sync.WaitGroup{},
			}

			// save the time before starting the link
			t0 := time.Now()

			// run the link forwarding algorithm in the background
			cfg.Wg.Add(1)
			go LinkFwdWithDelay(cfg)

			// read the expected number of frames or timeout after a minute.
			got := []*Frame{}
			timer := time.NewTimer(time.Minute)
			defer timer.Stop()
			for len(got) < len(tc.expect) {
				select {
				case frame := <-writer.Frames():
					got = append(got, frame)
				case <-timer.C:
					t.Fatal("we have been reading frames for too much time")
				}
			}

			// tell the network stack it can shut down now.
			reader.CloseNetworkStack()

			// wait for the algorithm to terminate.
			cfg.Wg.Wait()

			elapsed := time.Since(t0)
			if elapsed < tc.expectRuntimeAtLeast {
				t.Fatal("expected runtime to be at least", tc.expectRuntimeAtLeast, "got", elapsed)
			}

			// compare the frames we obtained.
			if diff := cmp.Diff(tc.expect, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
