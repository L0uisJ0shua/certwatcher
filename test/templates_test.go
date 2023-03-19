package main

import (
	templates "pkg/types"
	core "pkg/core"
	"testing"
)


func TestTemplates(t *testing.T) {

	// Declara e inicializa a variável options com um struct templates.Options
	var options = templates.Options{
		Templates: []string{"discover-dev-log-files", "git-config-exposure", "testing"}, // options.Templates[]string{} CLI Comand Line Interface
	}

	// Chama a função Templates com as opções preenchidas com valores fictícios
	templates, paths := core.Templates(options)

	for _, template := range templates {
		t.Log(template.Keywords, template.Matchers, template.TLDs, template.Requests, template.Severity, paths)
	}
}

