package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the plugins.configs.client-key-policy subtree of the CPA config.
type Config struct {
	Enabled  bool `yaml:"enabled"`
	Priority int  `yaml:"priority"`

	Vault VaultConfig `yaml:"vault"`
	CPA   CPAConfig   `yaml:"cpa"`

	// ClientIDHeader optionally carries the client id that a client also reads
	// from Vault. When present the plugin looks the key up by id instead of by hash.
	ClientIDHeader string `yaml:"client_id_header"`
	// RefreshInterval controls how often policies and keys are re-read from Vault.
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

// VaultConfig describes how the plugin reaches Vault / OpenBao.
type VaultConfig struct {
	Address   string `yaml:"address"`
	Namespace string `yaml:"namespace"`
	// Mount is the KV v2 secrets engine mount.
	Mount string `yaml:"mount"`
	// Prefix is the path inside the mount that the plugin owns.
	Prefix string `yaml:"prefix"`

	// AuthMethod is "token" or "approle".
	AuthMethod   string `yaml:"auth_method"`
	TokenEnv     string `yaml:"token_env"`
	AppRoleMount string `yaml:"approle_mount"`
	RoleIDEnv    string `yaml:"role_id_env"`
	SecretIDEnv  string `yaml:"secret_id_env"`

	CACert        string `yaml:"ca_cert"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify"`
}

// CPAConfig describes how the plugin reads the provider/model catalog from CPA.
type CPAConfig struct {
	ManagementURL    string        `yaml:"management_url"`
	ManagementKeyEnv string        `yaml:"management_key_env"`
	CatalogInterval  time.Duration `yaml:"catalog_interval"`
}

func defaultConfig() Config {
	return Config{
		Enabled:  true,
		Priority: 100,
		Vault: VaultConfig{
			Address:      "http://127.0.0.1:8200",
			Mount:        "secret",
			Prefix:       "cliproxyapi",
			AuthMethod:   "token",
			TokenEnv:     "VAULT_TOKEN",
			AppRoleMount: "approle",
			RoleIDEnv:    "VAULT_ROLE_ID",
			SecretIDEnv:  "VAULT_SECRET_ID",
		},
		CPA: CPAConfig{
			ManagementURL:    "http://127.0.0.1:8317",
			ManagementKeyEnv: "CPA_MANAGEMENT_KEY",
			CatalogInterval:  time.Minute,
		},
		ClientIDHeader:  "X-CPA-Client-Id",
		RefreshInterval: time.Minute,
	}
}

func parseConfig(raw []byte) (Config, error) {
	cfg := defaultConfig()
	if len(strings.TrimSpace(string(raw))) > 0 {
		if errUnmarshal := yaml.Unmarshal(raw, &cfg); errUnmarshal != nil {
			return Config{}, fmt.Errorf("decode plugin config: %w", errUnmarshal)
		}
	}
	cfg.Vault.Address = strings.TrimRight(strings.TrimSpace(cfg.Vault.Address), "/")
	cfg.Vault.Mount = strings.Trim(strings.TrimSpace(cfg.Vault.Mount), "/")
	cfg.Vault.Prefix = strings.Trim(strings.TrimSpace(cfg.Vault.Prefix), "/")
	cfg.Vault.Namespace = strings.Trim(strings.TrimSpace(cfg.Vault.Namespace), "/")
	cfg.Vault.AuthMethod = strings.ToLower(strings.TrimSpace(cfg.Vault.AuthMethod))
	cfg.CPA.ManagementURL = strings.TrimRight(strings.TrimSpace(cfg.CPA.ManagementURL), "/")
	cfg.ClientIDHeader = strings.TrimSpace(cfg.ClientIDHeader)
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = time.Minute
	}
	if cfg.CPA.CatalogInterval <= 0 {
		cfg.CPA.CatalogInterval = time.Minute
	}
	if cfg.Vault.Address == "" {
		return Config{}, fmt.Errorf("vault.address is required")
	}
	if cfg.Vault.Mount == "" {
		return Config{}, fmt.Errorf("vault.mount is required")
	}
	switch cfg.Vault.AuthMethod {
	case "token", "approle":
	default:
		return Config{}, fmt.Errorf("vault.auth_method must be token or approle")
	}
	return cfg, nil
}

func envValue(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}
