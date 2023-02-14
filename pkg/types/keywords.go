package types

type Keywords struct {
	Info struct {
		Name        string   `yaml:"name"`
		Author      string   `yaml:"author"`
		Description string   `yaml:"description"`
		Classification struct {
			ID   string `yaml:"id"`
			Type string `yaml:"type"`
			Country string `yaml:"country"`
			Tags  []string `yaml:"tags"`
		} `yaml:"classification"`
		References []string `yaml:"references"`
		Keywords []string `yaml:"keywords"`
		Subject  struct {
			C  string `yaml:"C"`
			ST string `yaml:"ST"`
			L  string `yaml:"L"`
			O  string `yaml:"O"`
			OU string `yaml:"OU"`
			EmailAddress string `yaml:"emailAddress"`
			CN string `yaml:"CN"`
			UnstructuredName string `yaml:"unstructuredName"`
		} `yaml:"subject"`
		Issuer string `yaml:"issuer"`
		Response []struct {
			StatusCode int `yaml:"status_code"`
		} `yaml:"response"`
	} `yaml:"info"`
}