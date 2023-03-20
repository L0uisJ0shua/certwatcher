package main

import (
	templates "pkg/types"
	core "pkg/core"
	"testing"
)


func TestTemplates(t *testing.T) {

	// Declara e inicializa a variável options com um struct templates.Options
	var options = templates.Options{
		Templates: []string{"git-metadata-exposure"}, // options.Templates[]string{} CLI Comand Line Interface
	}

	// Chama a função Templates com as opções preenchidas com valores fictícios
	templates, paths, matchers := core.Templates(options)

	for _, template := range templates {
		t.Log( template, matchers, paths)
	}
}

