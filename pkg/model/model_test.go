package model

import (
	"encoding/json"
	"matchers/matchers.go/model"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	info := model.Info{
		ID:          "Identified of the template",
		Name:        "Testing Template Name",
		Author:      stringslice.StringSlice{Value: []string{"unknow", "OpenAI"}},
		Description: "A description for Template",
		Severity:    severity.Holder{Severity: severity.High},
		Reference:   stringslice.NewRaw("Reference1"),
		Classification: &model.Classification{
			Country: "Any",
			Tags:    stringslice.StringSlice{Value: []string{"wordpress", "exposure", "nothiing", " "}},
		},
	}

	result, err := json.Marshal(&info)

	assert.Nil(t, err)

	expected := `{"ID":"Identified of the template","Name":"Testing Template Name","Author":["unknow","OpenAI"],"description":"A description for Template","reference":"Reference1","severity":"high","classification":{"Country":"Any","Tags":["wordpress","exposure","nothiing"," "],"cve-id":null,"cwe-id":null}}`
	assert.Equal(t, expected, string(result))
}
