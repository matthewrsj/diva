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
	"errors"
	"os"

	"github.com/clearlinux/diva/diva"
	"github.com/clearlinux/diva/internal/config"
	"github.com/clearlinux/diva/internal/helpers"
	"github.com/clearlinux/diva/manifests"
	"github.com/clearlinux/diva/pkginfo"
	"github.com/spf13/cobra"
)

type manifestCmdFlags struct {
	versionFrom string
	versionTo   string
	repoName    string
}

// flags passed in as args
var manifestFlags manifestCmdFlags

func init() {
	verifyManCmd.Flags().StringVarP(&manifestFlags.versionFrom, "from", "f", "0", "From version to check")
	verifyManCmd.Flags().StringVarP(&manifestFlags.versionTo, "to", "t", "0", "To version to check")
	verifyManCmd.Flags().StringVarP(&manifestFlags.repoName, "reponame", "r", "clear", "optional repo name")
}

var verifyManCmd = &cobra.Command{
	Use:   "manifests",
	Short: "Verify manifests correctly reflect changes between two repo versions",
	Long: `Verify manifests in the <to> version correctly reflect the changes in the repo
between <from> and <to> versions.`,
	Run: runVerifyManifests,
}

func runVerifyManifests(cmd *cobra.Command, args []string) {
	if manifestFlags.versionFrom == "0" || manifestFlags.versionTo == "0" {
		helpers.FailIfErr(errors.New("must supply a both --from and --to arguments"))
	}

	uf := config.UInfo{Ver: manifestFlags.versionFrom}
	ut := config.UInfo{Ver: manifestFlags.versionTo}

	repoF, err := pkginfo.NewRepo(conf, &uf)
	helpers.FailIfErr(err)

	repoT, err := pkginfo.NewRepo(conf, &ut)
	helpers.FailIfErr(err)

	mf, err := pkginfo.NewManifestInfo(conf, &uf)
	helpers.FailIfErr(err)

	mt, err := pkginfo.NewManifestInfo(conf, &ut)
	helpers.FailIfErr(err)

	helpers.PrintBegin("populating repo %s/%s", repoF.Name, repoF.Version)
	err = pkginfo.PopulateRepo(&repoF)
	helpers.FailIfErr(err)
	helpers.PrintComplete("repo %s/%s imported", repoF.Name, repoF.Version)

	helpers.PrintBegin("populating repo %s/%s", repoT.Name, repoT.Version)
	err = pkginfo.PopulateRepo(&repoT)
	helpers.FailIfErr(err)
	helpers.PrintComplete("repo %s/%s imported", repoT.Name, repoT.Version)

	r := diva.NewSuite("manifest check", "check manifest correctness for release")
	err = manifests.CheckAll(r, conf.Paths.CacheLocation, mf, mt, &repoF, &repoT)
	helpers.FailIfErr(err)

	if r.Failed > 0 {
		os.Exit(1)
	}
}
