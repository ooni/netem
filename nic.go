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

// nextNICName returns the next NIC name.
func nextNICName() string {
	return fmt.Sprintf("eth%d", nicID.Add(1))
}
