// Copyright © 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const (
	defaultConfig = "/usr/share/defaults/diva/config.toml"
	systemConfig  = "/etc/diva/config.toml"
	userConfig    = ".config/diva/config.toml" // under $HOME
	upstreamURL   = "https://download.clearlinux.org"
	bundleDefsURL = "https://github.com/clearlinux/clr-bundles"
)

// mixConfig defines the path and configuration of the mix workspace used by diva
type mixConfig struct {
	MixWorkSpace string `toml:"workspace"`
}

// pathConfig defines paths to various data used by diva
type pathConfig struct {
	BundleDefsRepo string `toml:"bundle_repository"`
	LocalRPMRepo   string `toml:"local_rpms"`
	CacheLocation  string `toml:"cache"`
}

// Config struct that defines the layout of the configuration file
type Config struct {
	Mixer         mixConfig  `toml:"mixer"`
	Paths         pathConfig `toml:"paths"`
	UpstreamURL   string     `toml:"upstream_url"`
	BundleDefsURL string     `toml:"bundles_url"`
}

// FetchingFlags are the command line flags used by the download, import, and
// fetch binaries.
type FetchingFlags struct {
	MixName         string
	Version         string
	Latest          bool
	UpstreamURL     string
	UpstreamRepoURL string
	RPMCache        string
	BinaryRPM       bool
	SourceRPM       bool
	DebugRPM        bool
	BundleURL       string
	BundleCache     string
	Update          bool
	Recursive       bool
}

// UInfo contains information used by all commands that is defaulted with
// config values, and updated with flags and other constraints to create
// the different data structs.
type UInfo struct {
	Ver         string
	Latest      bool
	URL         string
	MixName     string
	Update      bool
	CacheLoc    string
	RepoURL     string
	RPMCache    string
	RPMType     string
	BundleURL   string
	BundleCache string
	Recursive   bool
	MinVer      uint
}

// UpdateConfigInstance modifies the default config instance values with any
// args that were passed in as flags
func UpdateConfigInstance(conf *Config, u UInfo) {
	if u.URL != "" {
		conf.UpstreamURL = u.URL
	}

	// TODO: u.CacheLoc has no way of being modified from args yet
	if u.CacheLoc != "" {
		conf.Paths.CacheLocation = u.CacheLoc
	}

	if u.BundleURL != "" {
		conf.BundleDefsURL = u.BundleURL
	}

	if u.RPMCache != "" {
		conf.Paths.LocalRPMRepo = u.RPMCache
	}

	if u.BundleCache != "" {
		conf.Paths.BundleDefsRepo = u.BundleCache
	}
}

// NewUinfo creates a new UInfo object from the FetchingFlags and config instance
func NewUinfo(flags FetchingFlags, conf *Config) UInfo {
	u := UInfo{
		Ver:         flags.Version,
		Latest:      flags.Latest,
		URL:         flags.UpstreamURL,
		MixName:     flags.MixName,
		Update:      flags.Update,
		RepoURL:     flags.UpstreamRepoURL,
		Recursive:   flags.Recursive,
		RPMCache:    flags.RPMCache,
		BundleURL:   flags.BundleURL,
		BundleCache: flags.BundleCache,
	}
	UpdateConfigInstance(conf, u)
	return u
}

// DefaultConf is the default, and last fall back for the config object
func DefaultConf() Config {
	ws := filepath.Join(os.Getenv("HOME"), "clearlinux")
	return Config{
		mixConfig{
			filepath.Join(ws, "mix"),
		},
		pathConfig{
			filepath.Join(ws, "data/clr-bundles"),
			filepath.Join(ws, "repo"),
			filepath.Join(ws, "data"),
		},
		upstreamURL,
		bundleDefsURL,
	}
}

// ReadConfig reads configuration files on the system from default locations or
// at the path passed to configPath. The first configuration file found will be
// read. The configuration file paths are checked in the following order:
//
// defaultConfig "/usr/share/defaults/diva/config.toml"
// systemConfig  "/etc/diva/config.toml"
// userConfig    "$HOME/.config/diva/config.toml"
func ReadConfig(configPath string) (*Config, error) {
	var err error
	c := DefaultConf()
	userConfPath := filepath.Join(os.Getenv("HOME"), userConfig)
	// return the first configuration file found, check in the following order
	order := []string{configPath, userConfPath, systemConfig, defaultConfig}
	for _, path := range order {
		// configPath may be empty
		if path == "" {
			continue
		}
		_, err = toml.DecodeFile(path, &c)
		// if the file isn't found, try the next one
		if os.IsNotExist(err) {
			continue
		}
		// file found, return result of decode
		return &c, err
	}

	// no configuration file, return compiled defaults
	return &c, nil
}
