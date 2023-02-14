package yamlreader

import (
	"io/ioutil"
	"log"
	"gopkg.in/yaml.v2"
)

// ReadYAML lê uma string YAML ou um arquivo YAML e retorna um struct preenchido com os dados
func ReadYAML(src interface{}, v interface{}) error {
	var data []byte
	var err error

	switch s := src.(type) {
	case string:
		// Lê o conteúdo do arquivo YAML
		data, err = ioutil.ReadFile(s)
		if err != nil {
			log.Printf("Error: %v", err)
			return err
		}
	case []byte:
		data = s
	default:
		log.Printf("Error: Invalid source type %T", s)
		return err
	}

	// Decodifica o conteúdo para o struct passado como parâmetro
	err = yaml.Unmarshal(data, v)
	if err != nil {
		log.Printf("Error: %v", err)
		return err
	}

	return nil
}