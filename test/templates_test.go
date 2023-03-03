package main

import (
	"testing"
	templates "pkg/types"
	core "pkg/core"
)

func TestTemplates(t *testing.T) {

	// Declara e inicializa a variável options com um struct templates.Options preenchido com valores fictícios

	// Bug when you pass more than 1 yaml tags are multiplied.
	var options = templates.Options{
		Templates: []string{"fas-keywords-test", "fas-keywords-score", "fas-keywords-malware", "fas-keywords-banks"}, // options.Templates[]string{} CLI Comand Line Interface
	}

	// Chama a função Templates com as opções preenchidas com valores fictícios
	keywords, tlds, matchers := core.Templates(options)

	t.Log(keywords, tlds, matchers)
}
