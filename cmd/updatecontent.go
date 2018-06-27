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
	"os"

	"github.com/clearlinux/diva/diva"
	"github.com/clearlinux/diva/internal/helpers"
	"github.com/clearlinux/diva/updatecontent"

	"github.com/spf13/cobra"
)

func init() {
	checkCmd.AddCommand(ucCmd)
	ucCmd.Flags().UintVarP(&ucFlags.version, "version", "v", 0, "version to check")
	ucCmd.Flags().BoolVarP(&ucFlags.recursive, "recursive", "r", false, "perform complete recursive check")
}

type ucCmdFlags struct {
	version   uint
	recursive bool
}

var ucFlags ucCmdFlags

var ucCmd = &cobra.Command{
	Use:   "updatecontent",
	Short: "Validate update file and pack content",
	Long: `Validate update content for <version> or latest if --version was not provided.
Validates that all file and pack content is available and correct and the m
local configuration and <version>. If --recursive was passed, perform the check
on all update content reachable through the manifests, otherwise validate only
the current version.`,
	Run: runUCCheck,
}

func runUCCheck(cmd *cobra.Command, args []string) {
	var err error
	v := ucFlags.version
	if v == 0 {
		v, err = helpers.GetLatestVersion(conf.UpstreamURL)
		if err != nil {
			helpers.Fail(err)
		}
	}

	results, err := UCCheck(v, ucFlags.recursive)
	if err != nil {
		helpers.Fail(err)
	}

	err = results.Print(os.Stdout)
	if err != nil {
		helpers.Fail(err)
	}

	if results.Failed > 0 {
		os.Exit(1)
	}
}

// UCCheck runs update content checks against manifests and their related file
// and pack contents
func UCCheck(version uint, recursive bool) (*diva.Results, error) {
	r := &diva.Results{Name: "updatecontent"}
	u := diva.UInfo{Ver: version, URL: conf.UpstreamURL, CacheLoc: conf.Paths.CacheLocation}
	if !recursive {
		u.MinVer = version
	}
	err := diva.FetchUpdate(u)
	if err != nil {
		return r, err
	}

	err = diva.FetchUpdateFiles(u)
	if err != nil {
		return r, err
	}

	checkManifestHashes(r, u.Ver, u.MinVer)
	checkFileHashes(r, u.Ver, u.MinVer)
	checkZeroPacks(r, u.Ver, u.MinVer)

	return r, err
}

func checkManifestHashes(r *diva.Results, version, minVer uint) {
	name := "Manifest hashes"
	desc := "check manifest hashes match hashes listed in MoM"
	err := updatecontent.CheckManifestHashes(conf.Paths.CacheLocation, version, minVer)
	r.Add(name, desc, err, false)
}

func checkFileHashes(r *diva.Results, version, minVer uint) {
	name := "File hashes"
	desc := "check file hashes match hashes listed in manifest"
	err := updatecontent.CheckFileHashes(conf.Paths.CacheLocation, version, minVer)
	r.Add(name, desc, err, false)
}

func checkZeroPacks(r *diva.Results, version, minVer uint) {
	name := "Zero packs"
	desc := "check zero pack content matches content listed in manifests"
	err := updatecontent.CheckZeroPacks(conf, version, minVer)
	r.Add(name, desc, err, false)
}
