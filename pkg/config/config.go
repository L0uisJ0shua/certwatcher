package config

import (
    "encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"io/ioutil"
	"gopkg.in/yaml.v3"
	log "github.com/projectdiscovery/gologger"
)

var (
	// Version represents the current version of the application
	Version = "0.1.2"
	// Name represents the name of the application
	Name = "certwatcher"
	// The `Notice` variable represents a notice about the current state of the application.
	Notice = "\n\nThis project is in active development not ready for production. \nPlease use a proxy to stay safe. Use at your own risk."
)

type OpenAIConfig struct {
	APIKey string `yaml:"apikey"`
}

// StreamConfig is the configuration struct for stream
type StreamConfig struct {
	Certstream CertstreamConfig `mapstructure:"certstream"`
	// List of domains to filter
	// Filters in the interaction with the issued certificates.
	// examples:
	//   - value: >
	//       []string{"www.example.com", "*.test.com"}
	Domains []string `mapstructure:"domains"`
	// This function is true the domains will be ignored
	// Default ignore is false
	// examples:
	// - ignore: true
	Ignore bool `mapstructure:"ignore"`
}

// CertstreamConfig is the configuration struct for certstream
type CertstreamConfig struct {
	Mode string `mapstructure:"mode"`
}

// LogConfig is the configuration struct for logging
type LogConfig struct {
	// Certwatcher logs file
	File string `mapstructure:"file"`
	// Debug Level set default to Info
	Level string `mapstructure:"level"`
}

type AppConfig struct {
	// Version
	Version string `json:"version"`
	// Name
	Name string `json:"name"`
	// Notice Message.
	Notice string `json:"notice"`
}

// Config is the configuration struct
type Config struct {
	Log       LogConfig    `mapstructure:"log"`
	Stream    StreamConfig `mapstructure:"stream"`
	OpenAI    OpenAIConfig `mapstructure:"openai"`
}

// Load Configuration JSON
func Load() (AppConfig, error) {
	path, err := GetConfigDir()
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to get path to executable: %w", err)
	}

	config := filepath.Join(path, "config.json")

	file, err := ioutil.ReadFile(config)
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var appConfig AppConfig
	err = json.Unmarshal(file, &appConfig)
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to decode config file: %w", err)
	}

	return appConfig, nil
}

// GetConfigDir returns the configuration directory
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

	createConfigFiles()

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

func createDefaultConfig() error {

	defaultConfig := Config{
		Log: LogConfig{
			File:  "/var/log/certwatcher.log",
			Level: "info",
		},
		Stream: StreamConfig{
			Certstream: CertstreamConfig{
				Mode: "live",
			},
			Domains: []string{},
			Ignore: false,
		},
	}
	// Convert the default config to YAML format
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return err
	}

	configPath, _ := GetConfigDir()

	// Write the YAML config file
	err = ioutil.WriteFile(filepath.Join(configPath, "config.yaml"), data, 0600)
	if err != nil {
		return err
	}

	return nil
}

func createJSONConfig() error {
	// Create a new Config struct
	config := AppConfig{
		Version: "0.1.2",
		Name:    "certwatcher",
		Notice:  "\n\nThis project is in active development not ready for production. \nPlease use a proxy to stay safe. Use at your own risk.",
	}

	// Convert the Config struct to JSON
	configJSON, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}

	configPath, _ := GetConfigDir()
	// Write the JSON to the config file
	err = ioutil.WriteFile(filepath.Join(configPath, "config.json"), configJSON, 0600)
	if err != nil {
		return err
	}

	return nil
}

func createConfigFiles() {
	if err := createDefaultConfig(); err != nil {
		log.Fatal().Msgf("Error creating default config file:", err)
	}

	if err := createJSONConfig(); err != nil {
		log.Fatal().Msgf("Error creating JSON config file:", err)
	}
}