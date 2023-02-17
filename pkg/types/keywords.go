package types

type Keywords struct {
	Info struct {
		Name           string `yaml:"name"`
		Author         string `yaml:"author"`
		Description    string `yaml:"description"`
		Classification struct {
			ID      string   `yaml:"id"`
			Type    string   `yaml:"type"`
			Country string   `yaml:"country"`
			Tags    []string `yaml:"tags"`
		} `yaml:"classification"`
		References []string `yaml:"references"`
		Keywords   []string `yaml:"keywords"`
		Tlds       []string `yaml:"tlds"`
		Response []struct {
			StatusCode int `yaml:"status_code"`
		} `yaml:"response"`
	} `yaml:"info"`
}
