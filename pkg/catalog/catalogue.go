package catalog

import "io"

type Catalog interface {
	// Add method to help

	// OpenFile open a file and returns an io.ReadCloser
	OpenFile(filename string) (io.ReadCloser, error)
	// GetTemplatesPath returns a list of absolute paths for the provided template list.
	GetTemplatesPath(path []string) ([]string, map[string]error)
	// Returns a list of absolute paths and filters by ID
	// Passing a list containing the names of the templates.
	GetTemplatesById(ids []string) ([]string, error)
	// Return a list of absolute paths
	// Return all templates of default directory
	GetAllTemplatesPath() ([]string, map[string]error)
}
