package main

import (
	core "pkg/core"
	templates "pkg/types"
	"testing"
)

func TestTemplates(t *testing.T) {

	// Declare and initialize the options variable with a templates.Options struct
	var options = templates.Options{
		Templates: []string{"git-metadata-exposure", "ads-malware-google", "default"}, // options.Templates[]string{} CLI Comand Line Interface
	}

	// Calls the Templates function with options filled in with dummy values C
	templates := core.Templates(options)

	for id, template := range templates {
		t.Log(id, template.Matchers)
	}
}
