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

package cmd

import (
	"github.com/clearlinux/diva/diva"
	"github.com/clearlinux/diva/internal/helpers"

	"github.com/spf13/cobra"
)

type allFetchFlags struct {
	version     string
	bundleURL   string
	upstreamURL string
	recursive   bool
}

var allFlags allFetchFlags

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch and cache various build information",
}

var fetchAllCmd = &cobra.Command{
	Use:   "all [--version <version>] [--bundleurl|--upstreamurl <url>]",
	Run:   runFetchAllCmd,
	Short: "Fetch metadata from <version> or latest available if <version> is not supplied",
	Long: `Fetch latest bundle definitions, RPM repository, and update manifests from <version>.
If <version> is not supplied, fetch latest available content. Pass
--upstreamurl to fetch RPMs and update metadata from a location other than the
configured Upstream URL and --bundleurl to fetch the bundle definitions from a
location other than default.

RPMs will be cached under the cache location defined in your configuration or
default to $HOME/clearlinux/data/rpms/<version>. Bundle definition files will
be placed at $HOME/clearlinux/projects/clr-bundles by default. Update metadata
will be cached under the cache location as well, defaulting to
$HOME/clearlinux/data/update/<version>.`,
}

var fetchBundlesCmd = &cobra.Command{
	Use:   "bundles [--bundleurl <url>]",
	Run:   runFetchBundlesCmd,
	Short: "Fetch bundle definition files",
	Long: `Fetch bundle definition files from https://github.com/clearlinux/clr-bundles or
<url> if --bundleurl is supplied. Places the bundle definition files in
$HOME/clearlinux/projects/clr-bundles by default.`,
}

var fetchRepoCmd = &cobra.Command{
	Use:   "repo [--version <version>] [--upstreamurl <url>]",
	Run:   runFetchRepoCmd,
	Short: "Fetch repo from <version> or latest if not supplied",
	Long: `Fetch the RPM repository at <version> from the upstream URL if <version> is
supplied, otherwise fetch the latest available. If --upstreamurl is supplied, fetch
from <url> instead of the configured/default upstream URL. The repository is
cached under the cache location defined in your configuration or default to
$HOME/clearlinux/data/rpms/<version>.`,
}

var fetchUpdateCmd = &cobra.Command{
	Use:   "update [--version <version>] [--upstreamurl <url>]",
	Run:   runFetchUpdateCmd,
	Short: "Fetch the update at <version> or latest if not supplied",
	Long: `Fetch the update at <version> from the upstream URL if <version> is supplied,
otherwise fetch the latest available. If --upstreamurl is supplied, fetch from
<url> instead of the configured/default upstream URL. The update data is cached
under the cache location defined in your configuration or default to
$HOME/clearlinux/data/update/<version>.`,
}

var fetchCmds = []*cobra.Command{
	fetchAllCmd,
	fetchBundlesCmd,
	fetchRepoCmd,
	fetchUpdateCmd,
}

func init() {
	for _, cmd := range fetchCmds {
		fetchCmd.AddCommand(cmd)
	}

	rootCmd.AddCommand(fetchCmd)

	fetchAllCmd.Flags().StringVarP(&allFlags.version, "version", "v", "", "version from which to pull data")
	fetchAllCmd.Flags().StringVarP(&allFlags.bundleURL, "bundleurl", "b", "", "URL from which to pull bundle definitions")
	fetchAllCmd.Flags().StringVarP(&allFlags.upstreamURL, "upstreamurl", "u", "", "URL from which to pull update metadata")

	fetchBundlesCmd.Flags().StringVarP(&allFlags.bundleURL, "bundleurl", "b", "", "URL from which to pull bundle definitions")

	fetchRepoCmd.Flags().StringVarP(&allFlags.version, "version", "v", "", "version from which to pull data")

	fetchUpdateCmd.Flags().StringVarP(&allFlags.version, "version", "v", "", "version from which to pull data")
	fetchUpdateCmd.Flags().StringVarP(&allFlags.upstreamURL, "upstreamurl", "u", "", "URL from which to pull update metadata")
	fetchUpdateCmd.Flags().BoolVarP(&allFlags.recursive, "recursive", "r", false, "recursively fetch all content referenced in update metadata")
}

func runFetchAllCmd(cmd *cobra.Command, args []string) {
	u, err := diva.GetUpstreamInfo(conf, allFlags.upstreamURL, allFlags.version, allFlags.recursive)
	if err != nil {
		helpers.Fail(err)
	}

	err = diva.FetchRepo(u)
	if err != nil {
		helpers.Fail(err)
	}

	err = diva.GetLatestBundles(conf, allFlags.bundleURL)
	if err != nil {
		helpers.Fail(err)
	}

	err = diva.FetchUpdate(u)
	if err != nil {
		helpers.Fail(err)
	}
}

func runFetchBundlesCmd(cmd *cobra.Command, args []string) {
	err := diva.GetLatestBundles(conf, allFlags.bundleURL)
	if err != nil {
		helpers.Fail(err)
	}
}

func runFetchRepoCmd(cmd *cobra.Command, args []string) {
	u, err := diva.GetUpstreamInfo(conf, allFlags.upstreamURL, allFlags.version, allFlags.recursive)
	if err != nil {
		helpers.Fail(err)
	}

	err = diva.FetchRepo(u)
	if err != nil {
		helpers.Fail(err)
	}
}

func runFetchUpdateCmd(cmd *cobra.Command, args []string) {
	u, err := diva.GetUpstreamInfo(conf, allFlags.upstreamURL, allFlags.version, allFlags.recursive)
	if err != nil {
		helpers.Fail(err)
	}

	err = diva.FetchUpdate(u)
	if err != nil {
		helpers.Fail(err)
	}

	err = diva.FetchUpdateFiles(u)
	if err != nil {
		helpers.Fail(err)
	}
}
