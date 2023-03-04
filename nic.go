package netem

//
// NIC naming (for log messages)
//

import (
	"fmt"
	"sync/atomic"
)

// nicID is the unique ID of each link NIC.
var nicID = &atomic.Int64{}

// newNICName constructs a new, unique name for a NIC.
func newNICName() string {
	return fmt.Sprintf("eth%d", nicID.Add(1))
}
