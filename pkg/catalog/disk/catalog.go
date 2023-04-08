package disk

import (
	"io"
	"os"
)
// Create new template helper implementation
type DiskCatalog struct {
	templatesDirectory string
}
// Create NewCatalog struct using provided input
func NewCatalog(directory string) *DiskCatalog  {
	catalog := &DiskCatalog{templatesDirectory: directory}
	return catalog
}
// OpenFile opens a file and returns an io.ReadCloser to the file.
// It is used to read template and payload files based on catalog responses.
func (d *DiskCatalog) OpenFile(filename string) (io.ReadCloser, error) {
	file, err := os.Open(filename)
	return file, err
}