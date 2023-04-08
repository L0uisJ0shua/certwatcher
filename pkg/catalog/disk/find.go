package disk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/projectdiscovery/gologger"
)

func (c *DiskCatalog) GetTemplatesPath(paths []string) ([]string, map[string]error) {
	processed := make(map[string]bool)
	templates := []string{}
	erred := make(map[string]error)

	for _, t := range paths {
		// Check if path has already been processed
		if processed[t] {
			continue
		}
		processed[t] = true

		// Get all files with ".yaml" extension in the directory
		tmplFiles, err := filepath.Glob(filepath.Join(t, "*.yaml"))
		if err != nil {
			erred[t] = err
			continue
		}

		// Add the template files to the templates slice
		// templates retorn all templates
		for _, tmpl := range tmplFiles {
			templates = append(templates, tmpl)
		}
	}

	return templates, erred
}

func (c *DiskCatalog) GetAllTemplatesPath() ([]string, map[string]error) {
	templates := []string{}
	processed := make(map[string]bool)
	erred := make(map[string]error)

	directory, err := c.ConvertPathToAbsolute(filepath.Join(templateDefaultDirectory, "certwatcher-templates"))

	if err != nil {
		log.Fatal().Msgf("Error getting absolute path for template directory: %v", err)
	}

	// Diretórios a serem pesquisados
	templateDirectories := []string{
		directory,
		// Adicionar outros diretórios a serem pesquisados aqui
	}

	// Combine the default template directory with any additional directories to be searched
	dirs := templateDirectories

	for _, dir := range dirs {

		// Check if path has already been processed
		if processed[dir] {
			continue
		}
		processed[dir] = true

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {

			if err != nil {
				erred[path] = err // adiciona o erro ao mapa 'erred' com a chave sendo o caminho do arquivo
				return err
			}

			if match, _ := filepath.Match("*.yaml", filepath.Base(path)); !info.IsDir() && match {
				templates = append(templates, path)
			}

			return nil
		})

		if err != nil {
			fmt.Println(err)
		}
	}

	return templates, erred
}

func (c *DiskCatalog) GetTemplatesById(ids []string) ([]string, error) {
	var templates []string

	// Recursively search for templates by ID
	// Templates are located in the default folder
	directory, err := c.ConvertPathToAbsolute(filepath.Join(templateDefaultDirectory, "certwatcher-templates"))
	if err != nil {
		return nil, fmt.Errorf("error getting absolute path for template directory: %v", err)
	}

	// Diretórios a serem pesquisados
	templateDirectories := []string{
		directory,
		// Adicionar outros diretórios a serem pesquisados aqui
	}

	// Combine the default template directory with any additional directories to be searched
	dirs := append(templateDirectories)

	for _, dir := range dirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("error walking directory: %v", err)
			}

			if match, _ := filepath.Match("*.yaml", filepath.Base(path)); !info.IsDir() && match {
				// Extrai o nome do arquivo
				fileName := filepath.Base(path)
				// Remove a extensão yaml do nome do arquivo
				fileId := strings.TrimSuffix(fileName, filepath.Ext(fileName))
				// Verifica se o id do arquivo está contido em algum dos ids
				for _, id := range ids {
					if id == fileId {
						templates = append(templates, path)
						break
					}
				}
			}
			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("error searching for templates: %v", err)
		}
	}

	if len(templates) == 0 {
		log.Fatal().Msgf("Could not find template %s\n", ids)
	}

	return templates, nil
}
func (c *DiskCatalog) ConvertPathToAbsolute(t string) (string, error) {
	if strings.Contains(t, "*") {
		file := filepath.Base(t)
		return file, nil
	}

	absPath, err := filepath.Abs(t)
	if err != nil {
		return "", err
	}

	return absPath, nil
}

func (c *DiskCatalog) IsDirectory(paths []string) bool {
	// Convert the path to absolute
	for _, v := range paths {
		absPath, err := c.ConvertPathToAbsolute(v)
		if err != nil {
			return false
		}

		// Check if the absolute path represents a directory
		fileInfo, err := os.Stat(absPath)
		if err != nil {
			return false
		}
		return fileInfo.IsDir()
	}

	return false
}

func (c *DiskCatalog) Find(path []string) ([]string, error) {

	switch {
	case c.IsDirectory(path):
		// Get the templates in the specifics directory
		// Call GetTemplatesPath function
		templates, errors := c.GetTemplatesPath(path)

		// Imprime quaisquer erros encontrados durante a pesquisa
		for path, err := range errors {
			fmt.Printf("Error searching %s: %v\n", path, err)
		}

		return templates, nil

	case len(path) == 0 && !c.IsDirectory(path):
		// Get all templates in the default directory
		// If path equals 0 and not a directory
		templates, errors := c.GetAllTemplatesPath()

		// Possibly we can handle and validate the
		// Templates in the future implementing a method

		// Imprime quaisquer erros encontrados durante a pesquisa
		for path, err := range errors {
			fmt.Printf("Error searching %s: %v\n", path, err)
		}

		return templates, nil

	default:
		// Get all templates in the default directory
		// If path equals 0 and not a directory
		templates, _ := c.GetTemplatesById(path)

		// Possibly we can handle and validate the
		// Templates in the future implementing a method

		return templates, nil
	}
}

var templateDefaultDirectory string

func init() {
	var err error
	templateDefaultDirectory, err = os.UserHomeDir()
	if err != nil {
		log.Fatal().Msgf("Could not template default directory %s\n", err)
	}
}
