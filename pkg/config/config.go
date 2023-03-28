package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	// Version represents the current version of the application
	Version = "0.1.2"

	// Name represents the name of the application
	Name = "certwatcher"
	// The `Notice` variable represents a notice about the current state of the application.
	Notice = "\n\nThis project is in active development not ready for production. \nPlease use a proxy to stay safe. Use at your own risk."
)

// Config is the configuration struct
type Config struct {
	Log    LogConfig    `mapstructure:"log"`
	Stream StreamConfig `mapstructure:"stream"`
	Match  []string     `mapstructure:"matchers"`
	Tmpl   []string     `mapstructure:"templates"`
}

// LogConfig is the configuration struct for logging
type LogConfig struct {
	File  string `mapstructure:"file"`
	Level string `mapstructure:"level"`
}

// StreamConfig is the configuration struct for stream
type StreamConfig struct {
	Certstream CertstreamConfig `mapstructure:"certstream"`
	Domains    []string         `mapstructure:"domains"`
}

// CertstreamConfig is the configuration struct for certstream
type CertstreamConfig struct {
	Mode string `mapstructure:"mode"`
}

type AppConfig struct {
	Version string `json:"version"`
	Name    string `json:"name"`
	Notice  string `json:"notice"`
}

// LoadVersion loads the version from a JSON file in the same directory as the executable
func LoadVersion() (AppConfig, error) {
	configPath, err := GetConfigDir()
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to get path to executable: %w", err)
	}

	versionFile := filepath.Join(configPath, "version.json")
	file, err := os.Open(versionFile)
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to open version file: %w", err)
	}
	defer file.Close()

	var appConfig AppConfig

	if err := json.NewDecoder(file).Decode(&appConfig); err != nil {
		return AppConfig{}, fmt.Errorf("failed to decode version file: %w", err)
	}

	return appConfig, nil
}

// GetConfigDir returns the nuclei configuration directory
func GetConfigDir() (string, error) {
	var (
		home string
		err  error
	)
	home, err = homedir.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "certwatcher"), nil
}

// LoadConfig loads the configuration from a YAML file
func LoadConfig() (Config, error) {
	configPath, _ := GetConfigDir()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.MkdirAll(configPath, 0755); err != nil {
			return Config{}, fmt.Errorf("failed to create config directory: %w", err)
		}
		return Config{}, fmt.Errorf("config file not found: %w", err)
	}

	viper.SetConfigFile(filepath.Join(configPath, "config.yaml"))

	if err := viper.ReadInConfig(); err != nil {
		return Config{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return config, nil
}
