package model

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
)

type Info struct {
	// description |
	// ID is the unique identifier of the template to be loaded.
	// examples:
	//   - id: "\"litespeed-directory-listing\""
	ID string `yaml:"id"`
	// description: |
	//   Name of the template.
	// examples:
	//   - name: "\"John Doe\""
	Name string `yaml:"name"`
	// description: |
	//   Author of the template.
	//   Multiple values can also be specified separated by commas.
	// examples:
	//   - author: "\"<username>\""
	Author stringslice.StringSlice `yaml:"author"`
	// description: |
	//   Description of the template.
	//   You can go in-depth here on what the template actually does.
	// examples:
	//   - description: "\"Laravel debug method enabled in HTTP response bodies\""
	//   - description: "\"List of commons Jenkins Token or Crumb.\""
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,example=Bower is a package manager which stores package information in the bower.json file"`
	// description: |
	//   References for the template.
	//
	//   This should contain links relevant to the template.
	//
	// examples:
	//   - value: >
	//       []string{"https://github.com/strapi/strapi", "https://github.com/getgrav/grav"}
	Reference stringslice.RawStringSlice `json:"reference,omitempty" yaml:"reference,omitempty" jsonschema:"title=references for the template,description=Links relevant to the template"`
	// description: |
	//   References for the template.
	//
	//   This should contain links relevant to the template.
	//
	// examples:
	//   - value: >
	//       []string{"https://github.com/strapi/strapi", "https://github.com/getgrav/grav"}
	Severity severity.Holder `json:"severity,omitempty" yaml:"severity,omitempty"`
	// description: |
	//   Classification contains classification information about the template include tags, country.
	// examples:
	// - country: Any
	// - tags: "\"exposure, wordpress, cms\""
	Classification *Classification `json:"classification,omitempty" yaml:"classification,omitempty" jsonschema:"title=classification info for the template,description=Classification information for the template"`
}

type Classification struct {
	Country string                  `yaml:"country"`
	Tags    stringslice.StringSlice `yaml:"tags"`
	//   - value: "\"CVE-2020-14420\""
	CVEID stringslice.StringSlice `json:"cve-id,omitempty" yaml:"cve-id,omitempty" jsonschema:"title=cve ids for the template,description=CVE IDs for the template,example=CVE-2020-14420"`
	// description: |
	//   CWE ID for the template.
	// examples:
	//   - value: "\"CWE-22\""
	CWEID stringslice.StringSlice `json:"cwe-id,omitempty" yaml:"cwe-id,omitempty" jsonschema:"title=cwe ids for the template,description=CWE IDs for the template,example=CWE-22"`
	// description: |
	//   CVSS Metrics for the template.
	// examples:
	//   - value: "\"3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\""
	CVSSMetrics string `json:"cvss-metrics,omitempty" yaml:"cvss-metrics,omitempty" jsonschema:"title=cvss metrics for the template,description=CVSS Metrics for the template,example=3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`
	// description: |
	//   CVSS Score for the template.
	// examples:
	//   - value: "\"9.8\""
	CVSSScore float64 `json:"cvss-score,omitempty" yaml:"cvss-score,omitempty" jsonschema:"title=cvss score for the template,description=CVSS Score for the template,example=9.8",`
}
