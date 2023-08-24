package netem

import (
	"errors"
	"testing"
)

func TestStartTopology(t *testing.T) {
	t.Run("AddHost", func(t *testing.T) {
		t.Run("we cannot add the same address more than once", func(t *testing.T) {
			topology, err := NewStarTopology(&NullLogger{})
			if err != nil {
				t.Fatal(err)
			}

			// it should be possible to add an host once
			if _, err := topology.AddHost("1.2.3.4", "0.0.0.0", &LinkConfig{}); err != nil {
				t.Fatal(err)
			}

			// the second time, it should fail
			_, err = topology.AddHost("1.2.3.4", "0.0.0.0", &LinkConfig{})
			if !errors.Is(err, ErrDuplicateAddr) {
				t.Fatal("not the error we expected", err)
			}
		})
	})
}
