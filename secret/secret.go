package secret

import (
	"fmt"
)

// Distro represents a Linux Distribution.
type Secret struct {
	Data     string
	Location string
}

// String returns a human-friendly representation of the Linux distribution.
func (s Secret) String() string {

	return fmt.Sprintf("%s %s", s.Location, s.Data)
}
