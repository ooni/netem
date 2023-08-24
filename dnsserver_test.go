package netem

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDNSConfig(t *testing.T) {
	t.Run("removing a nonexisting record does not cause any issue", func(t *testing.T) {
		dc := NewDNSConfig()
		dc.RemoveRecord("www.example.com")
	})

	t.Run("we can remove a previously added record", func(t *testing.T) {
		dc := NewDNSConfig()

		t.Run("the record should be there once we have added it", func(t *testing.T) {
			if err := dc.AddRecord("www.example.com", "www1.example.com", "1.2.3.4", "4.5.6.7"); err != nil {
				t.Fatal(err)
			}
			rec, good := dc.Lookup("www.example.com")
			if !good {
				t.Fatal("the record is not there")
			}
			expect := &DNSRecord{
				A: []net.IP{
					net.IPv4(1, 2, 3, 4),
					net.IPv4(4, 5, 6, 7),
				},
				CNAME: "www1.example.com.",
			}
			if diff := cmp.Diff(expect, rec); diff != "" {
				t.Fatal(diff)
			}

			t.Run("the record should disappear once we have removed it", func(t *testing.T) {
				dc.RemoveRecord("www.example.com")
				rec, good := dc.Lookup("www.example.com")
				if good {
					t.Fatal("expected the record to be nonexistent")
				}
				if rec != nil {
					t.Fatal("expected a nil record")
				}
			})
		})
	})
}
