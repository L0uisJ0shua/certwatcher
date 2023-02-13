package types

type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Description string   `yaml:"description"`
	Classification struct {
		ID   string `yaml:"id"`
		Type string `yaml:"type"`
		Country string `yaml:"country"`
		Tags []string `yaml:"tags"`
	} `yaml:"classification"`
	References []string `yaml:"references"`
	Request struct {
		Method string `yaml:"method"`
		URL string `yaml:"url"`
		Redirects bool `yaml:"redirects"`
		MaxRedirects int `yaml:"max-redirects"`
		Headers struct {
			UserAgent string `yaml:"User-Agent"`
		} `yaml:"headers"`
		Params struct {
			Q string `yaml:"q"`
		} `yaml:"params"`
		MatchersCondition string `yaml:"matchers-condition"`
		Matchers []struct {
			Type string `yaml:"type"`
			Part string `yaml:"part"`
			Words []string `yaml:"words"`
		} `yaml:"matchers"`
	} `yaml:"request"`
	Response []struct {
		StatusCode int `yaml:"status_code"`
	} `yaml:"response"`
}