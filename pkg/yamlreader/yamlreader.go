package yamlreader

import (
	"io/ioutil"
	"log"
	"gopkg.in/yaml.v2"
)

// ReadYAMLFile lê um arquivo YAML e retorna um struct preenchido com os dados
func ReadYAMLFile(filePath string, v interface{}) error {
	// Lê o conteúdo do arquivo YAML
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Printf("Error: %v", err)
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