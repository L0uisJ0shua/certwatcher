package disk

import (
	"testing"

	"io/ioutil"
	"pkg/catalog/disk"
)

func TestDiskGetTemplatesPath(t *testing.T) {
	// Create a DiskCatalog instance
	catalog := &disk.DiskCatalog{}

	// Create test paths
	paths := []string{"/home/r3dline/certwatcher-templates/exposures/file/apache/", "/home/r3dline/certwatcher-templates/testing/default"}

	// Call GetTemplatesPath function
	templates, errors := catalog.GetTemplatesPath(paths)
	loadedPaths := len(templates)

	// Imprime os caminhos de todos os arquivos .tmpl encontrados
	for _, tmpl := range templates {
		file, err := catalog.OpenFile(tmpl)
		if err != nil {
			// Tratar erro
		}
		defer file.Close() // Fechar arquivo após terminar de usá-lo

		// Ler conteúdo do arquivo
		contents, err := ioutil.ReadAll(file)
		if err != nil {
			// Tratar erro
		}

		// Usar o conteúdo do arquivo
		t.Log(string(contents))
	}
	// Show length templates
	t.Logf("loaded templates: %d", loadedPaths)

	// Imprime quaisquer erros encontrados durante a pesquisa
	for path, err := range errors {
		t.Logf("Error searching %s: %v\n", path, err)
	}
}

func TestDiskCatalog(t *testing.T) {

	// Create a DiskCatalog instance
	catalog := &disk.DiskCatalog{}

	// Create test paths
	paths := []string{"/home/r3dline/certwatcher-templates/exposures/file/apache/", "/home/r3dline/certwatcher-templates/testing/default/apache-dir-*"}

	t.Log(catalog, paths)

	for _, v := range paths {
		s, err := catalog.ConvertPathToAbsolute(v)

		t.Log(s, err)
	}

}

func TestIsDirectory(t *testing.T) {
	catalog := &disk.DiskCatalog{}

	// Test a directory path
	isDir := catalog.IsDirectory([]string{".."})
	if isDir {
		t.Errorf("Expected true, but got false for directory path")
	}

	// Test a file path
	isDir = catalog.IsDirectory([]string{"main.go"})
	if isDir {
		t.Errorf("Expected false, but got true for file path")
	}

	// Test a non-existent path
	isDir = catalog.IsDirectory([]string{"no-existing"})
	if isDir {
		t.Errorf("Expected false, but got true for non-existent path")
	}
}

func TestDiskCatalogFind(t *testing.T) {
	catalog := &disk.DiskCatalog{}

	t.Run("Find valid directory", func(t *testing.T) {
		templates, err := catalog.Find([]string{"/home/r3dline/certwatcher-templates/testing/validate"})
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
		if len(templates) != 35 {
			t.Errorf("Expected 35 templates, but got %v", len(templates))
		}
	})

	t.Run("Find valid templates", func(t *testing.T) {
		templates, err := catalog.Find([]string{"apache-dir-listing", "laravel-env-disclosure", "apache-guacamole", "default-apache-test-all"})
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}

		t.Log(templates)
		if len(templates) != 4 {
			t.Errorf("Expected 4 templates, but got %v", len(templates))
		}
	})

	t.Run("Find empty path or files", func(t *testing.T) {
		templates, err := catalog.Find([]string{})
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
		if len(templates) != 70 {
			t.Errorf("Expected 70 templates, but got %v", len(templates))
		}
	})

	t.Run("Find non-existent path", func(t *testing.T) {
		templates, err := catalog.Find([]string{"/nonexistent/path"})
		if err == nil {
			t.Errorf("Expected error, but got no error and templates %v", templates)
		}
		if len(templates) != 0 {
			t.Errorf("Expected 0 templates, but got %v", len(templates))
		}
	})
}
