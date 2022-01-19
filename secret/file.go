package secret

import (
	"github.com/anchore/stereoscope/pkg/file"
	"io"
)

// Distro represents a Linux Distribution.
type File struct {
	Reference file.Reference
	Reader    io.ReadCloser
}
