package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/messhio/messh/cli/internal/apitypes"
)

const defaultRegistry = "https://messh.io"

type config struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
}

func configDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "messh")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "messh")
}

func loadConfig() config {
	var c config
	if b, err := os.ReadFile(filepath.Join(configDir(), "config.json")); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

func saveSession(c config, token string) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "token"), []byte(token+"\n"), 0o600)
}

func loadToken() string {
	b, _ := os.ReadFile(filepath.Join(configDir(), "token"))
	return strings.TrimSpace(string(b))
}

// registryURL: $MESSH_REGISTRY, then the registry you logged in to, then messh.io.
func registryURL() string {
	if r := os.Getenv("MESSH_REGISTRY"); r != "" {
		return strings.TrimRight(r, "/")
	}
	if r := loadConfig().Registry; r != "" {
		return r
	}
	return defaultRegistry
}

type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient() *client {
	return &client{base: registryURL(), token: loadToken(), http: &http.Client{Timeout: 10 * time.Second}}
}

// apiError is a non-2xx response from the registry.
type apiError struct {
	Status int
	Body   apitypes.Error
}

func (e *apiError) Error() string {
	if e.Body.Message != "" {
		return e.Body.Message
	}
	return fmt.Sprintf("registry returned HTTP %d", e.Status)
}

func (c *client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "messh/"+version)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		e := &apiError{Status: resp.StatusCode}
		json.NewDecoder(resp.Body).Decode(&e.Body)
		return e
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *client) mustAuth() error {
	if c.token == "" {
		return errors.New("not logged in; run messh login")
	}
	return nil
}

func (c *client) profile(username string) (*apitypes.Profile, error) {
	var p apitypes.Profile
	if err := c.do("GET", "/"+username+".json", nil, &p); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return nil, fmt.Errorf("no messh user %q", username)
		}
		return nil, err
	}
	return &p, nil
}

func (c *client) keysText(username string) (string, error) {
	resp, err := c.http.Get(c.base + "/" + username + ".keys")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GET %s.keys: HTTP %d", username, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}
