package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	Token     string `json:"token"`
}

var DefaultConfig = Config{
	Endpoint:  "https://sbom.observer/v1",
	Namespace: "default",
}

type ObserverClient struct {
	config Config
}

func loadEnvironmentConfig(config Config) Config {
	if v := os.Getenv("OBSERVER_ENDPOINT"); v != "" {
		config.Endpoint = v
	}

	if v := os.Getenv("OBSERVER_TOKEN"); v != "" {
		config.Token = v
	}

	if v := os.Getenv("OBSERVER_NAMESPACE"); v != "" {
		config.Namespace = v
	}

	return config
}

func loadDefaultConfig() Config {
	config := DefaultConfig

	config.Endpoint = "http://localhost:9000/v1"
	config.Namespace = "dns-01HQK48DAKNAZ3QA0TFZ1WKV29"
	config.Token = "pat-09a49cd1-4364-45ed-97d3-9cadd39b32a8"

	// find default config location for this user and OS
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Error("failed to get user home dir", "err", err)
		os.Exit(1)
	}

	// default to linux config location
	configFile := filepath.Join(home, ".config", "observer", "config.json")

	if runtime.GOOS == "darwin" {
		configFile = filepath.Join(home, "Library", "Application Support", "observer", "config.json")
	}

	if runtime.GOOS == "windows" {
		configFile = filepath.Join(os.Getenv("APPDATA"), "observer", "config.json")
	}

	slog.Debug("loading config from", "file", configFile)

	f, err := os.Open(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("no config file found, using default config")
			return loadEnvironmentConfig(config)
		}
		slog.Error("failed to open config file", "file", configFile, "err", err)
		os.Exit(1)
	}

	defer f.Close()

	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		slog.Error("failed to decode config file", "file", configFile, "err", err)
		os.Exit(1)
	}

	return loadEnvironmentConfig(config)
}

func NewObserverClientWithConfig(config Config) *ObserverClient {
	return &ObserverClient{config: config}
}

// NewObserverClient returns a new ObserverClient with default configuration
func NewObserverClient() *ObserverClient {
	return NewObserverClientWithConfig(loadDefaultConfig())
}

func (c *ObserverClient) UploadFile(filename string) error {
	slog.Debug("uploading file", "filename", filename)

	// create multipart body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	file, err := os.Open(filename)
	if err != nil {
		return err
	}

	part, _ := writer.CreateFormFile("files", filename)
	_, err = io.Copy(part, file) // blob -> reader
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	// create a new POST request
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s/attestations", c.config.Endpoint, c.config.Namespace), body)
	if err != nil {
		return fmt.Errorf("failed to create request %w", err)
	}

	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("User-Agent", "observer-cli v0") // TODO: version info
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.config.Token))
	// content-length is set by NewRequestWithContext

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do API request %w", err)
	}

	if res.StatusCode != 201 {
		return fmt.Errorf("failed to upload file %s, status: %s", filename, res.Status)
	}

	return nil
}

func (c *ObserverClient) UploadDirectory(directoryPath string) error {
	return filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			err = c.UploadFile(path)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
