package main

import (
	templates "pkg/types"
	core "pkg/core"
	"testing"
)


func TestTemplates(t *testing.T) {

	// Declara e inicializa a variável options com um struct templates.Options preenchido com valores fictícios
	var options = templates.Options{
		Templates: []string{"fas-keywords-test"}, // options.Templates[]string{} CLI Comand Line Interface
	}

	// Chama a função Templates com as opções preenchidas com valores fictícios
	keywords, tlds, matchers := core.Templates(options)

	t.Log(keywords, tlds, matchers)
}

