package templates

import (
	"errors"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// Directory é o diretório padrão para buscar os arquivos de template
var Directory = filepath.Join(os.Getenv("HOME"), "certwatcher-templates", "templates")

// FindTemplateByID busca os templates com os IDs especificados em todas as pastas do diretório padrão e em quaisquer pastas adicionais especificadas, retornando os caminhos dos arquivos YAML correspondentes.
func Find(templateID []string, additionalDirs ...string) ([]string, error) {
	// Combine o diretório padrão de template com quaisquer diretórios adicionais a serem pesquisados
	dirs := append([]string{Directory}, additionalDirs...)

	// Crie um mapa para armazenar os caminhos dos arquivos de template encontrados
	templatePaths := make(map[string]string)

	// Pesquise os arquivos de template em cada diretório especificado
	for _, dir := range dirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && filepath.Ext(path) == ".yaml" {
				// Obtenha o nome do arquivo sem a extensão
				filename := filepath.Base(path[:len(path)-len(filepath.Ext(path))])

				// Verifique se o nome do arquivo corresponde a um dos IDs de template especificados
				for _, id := range templateID {
					if filename == id {
						// Se o arquivo corresponder, armazene o caminho completo do arquivo no mapa
						templatePaths[id] = path
					}
				}
			}
			return nil
		})
		if err != nil {
			log.Fatalf("Erro ao pesquisar por templates: %s", err.Error())
		}
	}

	// Verifique se foram encontrados arquivos de template para cada ID de template especificado
	missingTemplates := make([]string, 0)
	for _, id := range templateID {
		if _, ok := templatePaths[id]; !ok {
			missingTemplates = append(missingTemplates, id)
		}
	}
	if len(missingTemplates) > 0 {
		return nil, errors.New("Templates com IDs " + string(missingTemplates[0]) + " não encontrados")
	}

	// Converta o mapa de caminhos de arquivo para uma slice de caminhos de arquivo ordenados pelos IDs de template fornecidos
	sortedTemplatePaths := make([]string, len(templateID))
	for i, id := range templateID {
		sortedTemplatePaths[i] = templatePaths[id]
	}

	return sortedTemplatePaths, nil
}