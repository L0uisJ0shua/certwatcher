package types

import (
	"github.com/projectdiscovery/goflags"
)

// Options defines the configuration structure for the CertWatcher program

type Options struct {

	// Templates
	// This field contains the list of YAML templates that will be loaded by the program
	Templates goflags.StringSlice
	// YAML with keywords
	// This field specifies the YAML file that contains the keywords that the program will search for
	Keywords goflags.StringSlice
	// Validate YAML templates
	// This field specifies if the program should validate the YAML templates before loading them
	Validate bool
	// Basic Configuration to Interact with Selenium and the Web Browser
	// If true, the program will run in headless mode
	Headless bool
	// The number of seconds the program will wait for each page in headless mode
	PageTimeout int
	// If true, the program will capture screenshots
	PageScreenShot bool

	// General Config
	Verbose bool
	VerboseVerbose bool
	Debug   bool
	Version bool

	Retries int
	Timeout int
}


// DefaultOptions returns default options for nuclei
func DefaultOptions() *Options {
	return &Options{
		Timeout:                 5,
		Retries:                 1,
	}
}