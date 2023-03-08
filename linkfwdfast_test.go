package netem

import (
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestLinkFwdFast(t *testing.T) {

	// testcase describes a test case for [LinkFwdFast]
	type testcase struct {
		// name is the name of this test case
		name string

		// contains the list of frames that we should emit
		emit []*Frame

		// expect contains the list of frames we expect
		expect []*Frame
	}

	var testcases = []testcase{{
		name:   "when we send no frame",
		emit:   []*Frame{},
		expect: []*Frame{},
	}, {
		name: "when we send some frames",
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
				OneWayDelay: 0,
				PLR:         0,
				Reader:      reader,
				Writer:      writer,
				Wg:          &sync.WaitGroup{},
			}

			// run the link forwarding algorithm in the background
			cfg.Wg.Add(1)
			go LinkFwdFast(cfg)

			// wait for the algorithm to terminate.
			cfg.Wg.Wait()

			// compare the frames we obtained.
			if diff := cmp.Diff(tc.expect, writer.Frames()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
