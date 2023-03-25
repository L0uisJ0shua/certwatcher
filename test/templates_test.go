package main

import (
	core "pkg/core"
	templates "pkg/types"
	"testing"
)

func TestTemplates(t *testing.T) {

	// Declara e inicializa a variável options com um struct templates.Options
	var options = templates.Options{
		Templates: []string{"git-metadata-exposure", "ads-malware-google", "example"}, // options.Templates[]string{} CLI Comand Line Interface
	}

	// Chama a função Templates com as opções preenchidas com valores fictícios
	templates, _, _ := core.Templates(options)

	for id, template := range templates {
		t.Log(id, template.Matchers)
	}
}
