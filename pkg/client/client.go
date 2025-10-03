package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/types"
)

type Config struct {
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	Token     string `json:"token"`
}

var DefaultConfig = Config{
	Endpoint:  "https://cloud.sbom.observer",
	Namespace: "default",
}

type ObserverClient struct {
	Config Config
}

func sanitizeEnvVar(value string) string {
	return strings.ReplaceAll(value, "/", "")
}

func loadEnvironmentConfig(config Config) Config {
	if v := os.Getenv("OBSERVER_ENDPOINT"); v != "" {
		config.Endpoint = v
	}

	if v := os.Getenv("OBSERVER_TOKEN"); v != "" {
		config.Token = sanitizeEnvVar(v)
	}

	if v := os.Getenv("OBSERVER_NAMESPACE"); v != "" {
		config.Namespace = sanitizeEnvVar(v)
	}

	return config
}

func loadDefaultConfig() Config {
	config := DefaultConfig

	// find default Config location for this user and OS
	home, err := os.UserHomeDir()
	if err != nil {
		log.Error("failed to get user home dir", "err", err)
		os.Exit(1)
	}

	// default to linux Config location
	configFile := filepath.Join(home, ".Config", "observer", "Config.json")

	if runtime.GOOS == "darwin" {
		configFile = filepath.Join(home, "Library", "Application Support", "observer", "Config.json")
	}

	if runtime.GOOS == "windows" {
		configFile = filepath.Join(os.Getenv("APPDATA"), "observer", "Config.json")
	}

	log.Debug("loading Config from", "file", configFile)

	f, err := os.Open(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("no Config file found, using default Config")
			return loadEnvironmentConfig(config)
		}
		log.Error("failed to open Config file", "file", configFile, "err", err)
		os.Exit(1)
	}

	defer f.Close()

	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		log.Error("failed to decode Config file", "file", configFile, "err", err)
		os.Exit(1)
	}

	return loadEnvironmentConfig(config)
}

func NewObserverClientWithConfig(config Config) *ObserverClient {
	return &ObserverClient{Config: config}
}

// NewObserverClient returns a new ObserverClient with default configuration
func NewObserverClient() *ObserverClient {
	return NewObserverClientWithConfig(loadDefaultConfig())
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

type FileSource func(w io.Writer) error

func (c *ObserverClient) uploadSource(url string, filename string, source FileSource) ([]byte, error) {
	log.Debug("uploading file", "filename", filename)

	// create multipart body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, _ := writer.CreateFormFile("files", filename)

	// collect contents
	err := source(part)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	// create a new POST request
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request %w", err)
	}

	// content-length is set by http.NewRequest
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("User-Agent", fmt.Sprintf("observer-cli %s (%s %s) %s/%s", types.Version, types.Commit, types.Date, runtime.GOOS, runtime.GOARCH))

	if c.Config.Token != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.Config.Token))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do API request %w", err)
	}

	if res.StatusCode != 201 && res.StatusCode != 200 {
		if res.StatusCode == 401 || res.StatusCode == 403 {
			if c.Config.Token == "" {
				log.Fatal("no token found, please set OBSERVER_TOKEN environment variable")
			}
		}

		return nil, fmt.Errorf("failed to upload file %s, status: %s", filename, res.Status)
	}

	// read response body
	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body %w", err)
	}

	return responseBody, nil
}

func (c *ObserverClient) uploadFile(url string, filename string) ([]byte, error) {
	return c.uploadSource(url, filename, func(w io.Writer) error {
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(w, file)
		if err != nil {
			return err
		}

		return nil
	})

}

func (c *ObserverClient) UploadSource(filename string, source FileSource) error {
	_, err := c.uploadSource(fmt.Sprintf("%s/api/v1/%s/attestations", c.Config.Endpoint, c.Config.Namespace), filename, source)
	return err
}

func (c *ObserverClient) UploadFile(filename string) error {
	_, err := c.uploadFile(fmt.Sprintf("%s/api/v1/%s/attestations", c.Config.Endpoint, c.Config.Namespace), filename)
	return err
}
