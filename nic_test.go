package netem

import (
	"errors"
	"testing"
)

func TestMockableNIC(t *testing.T) {
	t.Run("MockFrameAvailable", func(t *testing.T) {
		ch := make(chan any, 1)
		ch <- true

		nic := &MockableNIC{
			MockFrameAvailable: func() <-chan any {
				return ch
			},
		}

		value := <-nic.FrameAvailable()
		if flag, good := value.(bool); !good || !flag {
			t.Fatal("FrameAvailable is broken")
		}
	})

	t.Run("MockReadFrameNonblocking", func(t *testing.T) {
		expect := errors.New("mocked error")

		nic := &MockableNIC{
			MockReadFrameNonblocking: func() (*Frame, error) {
				return nil, expect
			},
		}

		frame, err := nic.ReadFrameNonblocking()
		if !errors.Is(err, expect) {
			t.Fatal("unexpected error", err)
		}
		if frame != nil {
			t.Fatal("expected nil frame")
		}
	})

	t.Run("MockStackClosed", func(t *testing.T) {
		ch := make(chan any, 1)
		ch <- true

		nic := &MockableNIC{
			MockStackClosed: func() <-chan any {
				return ch
			},
		}

		value := <-nic.StackClosed()
		if flag, good := value.(bool); !good || !flag {
			t.Fatal("FrameAvailable is broken")
		}
	})

	t.Run("MockClose", func(t *testing.T) {
		expect := errors.New("mocked error")

		nic := &MockableNIC{
			MockClose: func() error {
				return expect
			},
		}

		err := nic.Close()
		if !errors.Is(err, expect) {
			t.Fatal("unexpected error", err)
		}
	})

	t.Run("MockIPAddress", func(t *testing.T) {
		expect := "1.1.1.1"

		nic := &MockableNIC{
			MockIPAddress: func() string {
				return expect
			},
		}

		if v := nic.IPAddress(); v != expect {
			t.Fatal("unexpected value", v)
		}
	})

	t.Run("MockInterfaceName", func(t *testing.T) {
		expect := "eth0"

		nic := &MockableNIC{
			MockInterfaceName: func() string {
				return expect
			},
		}

		if v := nic.InterfaceName(); v != expect {
			t.Fatal("unexpected value", v)
		}
	})

	t.Run("MockWriteFrame", func(t *testing.T) {
		expectedErr := errors.New("mocked error")
		expectedFrame := NewFrame(nil)
		var got *Frame

		nic := &MockableNIC{
			MockWriteFrame: func(frame *Frame) error {
				got = frame
				return expectedErr
			},
		}
		err := nic.WriteFrame(expectedFrame)
		if !errors.Is(err, expectedErr) {
			t.Fatal("unexpected error", err)
		}
		if got != expectedFrame {
			t.Fatal("got unexpected frame")
		}
	})
}
