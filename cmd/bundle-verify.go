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
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/clearlinux/diva/diva"
	"github.com/clearlinux/diva/internal/config"
	"github.com/clearlinux/diva/internal/helpers"
	"github.com/clearlinux/diva/pkginfo"
	"github.com/spf13/cobra"
)

type bundleCmdFlags struct {
	mixName string
	version string
	latest  bool
	bundle  string
}

// flags passed in as args
var bundleFlags bundleCmdFlags

func init() {
	verifyBundlesCmd.Flags().StringVarP(&bundleFlags.mixName, "name", "n", "clear", "name of data group")
	verifyBundlesCmd.Flags().StringVarP(&bundleFlags.version, "version", "v", "0", "version to check")
	verifyBundlesCmd.Flags().BoolVar(&bundleFlags.latest, "latest", false, "get the latest version from upstreamURL")
	verifyBundlesCmd.Flags().StringVarP(&bundleFlags.bundle, "bundle", "b", "", "bundle to check")
}

var verifyBundlesCmd = &cobra.Command{
	Use:   "bundles",
	Short: "Verify bundle definitions are complete, and packages exist within repo.",
	Long: `Verify bundles are complete by checking that all named packages within
bundle and package bundle files can be found in the configured repo. It also
ensures no include loops exist, and that the bundle filename matches the bundle
definition header TITLE. For a <bundle> or the default of all bundles. An
optional <name> and <version> may be used to specify a repo the bundle
packages completeness will run against with "clear" and "0" as the defaults.`,
	Run: runVerifyBundle,
}

func runVerifyBundle(cmd *cobra.Command, args []string) {
	u := config.UInfo{
		MixName: bundleFlags.mixName,
		Ver:     bundleFlags.version,
		Latest:  bundleFlags.latest,
	}

	repo, err := pkginfo.NewRepo(conf, &u)
	helpers.FailIfErr(err)

	helpers.PrintBegin("Populating repo")
	err = pkginfo.PopulateRepo(&repo)
	helpers.FailIfErr(err)
	helpers.PrintComplete("Repo populated successfully")

	bundleInfo, err := pkginfo.NewBundleInfo(conf, &u)
	helpers.FailIfErr(err)

	result := diva.NewSuite("bundle-verify", "validate bundle correctness")

	err = pkginfo.PopulateBundles(&bundleInfo, bundleFlags.bundle)
	helpers.FailIfErr(err)

	checkIncludeLoops(result, &bundleInfo)
	checkBundleDefinitionsComplete(result, &bundleInfo)
	checkBundleName(result, &bundleInfo)
	checkBundleHeaderTitleMatchesFile(result, &bundleInfo)
	checkBundleRPMs(result, &bundleInfo, &repo)

	err = checkIfPundleDeletesExist(result, bundleInfo.Tag)
	helpers.FailIfErr(err)

	err = checkIfBundleDeletesExist(result, bundleInfo.Tag)
	helpers.FailIfErr(err)

	if result.Failed > 0 {
		os.Exit(1)
	}
}

// checkIncludeLoops iterates the includes in the bundle definitions, and if
// an include is found with a false value associated then we know an include
// loop has been detected. The detection functionality is in the bundle library
func checkIncludeLoops(result *diva.Results, bundleInfo *pkginfo.BundleInfo) {
	var failures []string

	for _, bundle := range bundleInfo.BundleDefinitions {
		for k, v := range bundle.Includes {
			if !v {
				failures = append(failures, fmt.Sprintf("%s has include loop with %s", bundle.Name, k))
			}
		}
	}
	result.Ok(len(failures) == 0, "no include loops found")
	if len(failures) > 0 {
		result.Diagnostic("Include loop detected: \n" + strings.Join(failures, "\n"))
	}
}

// checkBundleDefinitionsComplete checks that bundle includes, direct packages,
// and recurisive dependent packages are not empty sets.
func checkBundleDefinitionsComplete(result *diva.Results, bundleInfo *pkginfo.BundleInfo) {
	var failures []string

	for _, bundle := range bundleInfo.BundleDefinitions {
		// A bundle should always include AT LEAST itself
		if len(bundle.Includes) == 0 {
			failures = append(failures, fmt.Sprintf("%s does not have any includes", bundle.Name))
		}

		// Every bundle needs at least one package, whether direct or from an
		// included bundle
		if len(bundle.AllPackages) == 0 {
			failures = append(failures, fmt.Sprintf("%s does not have any packages", bundle.Name))
		}

		// A bundle can have no direct packages, but it must include another bundle
		// other than itself.
		if len(bundle.DirectPackages) == 0 {
			if _, exists := bundle.Includes[bundle.Name]; exists && len(bundle.Includes) == 1 {
				failures = append(failures, fmt.Sprintf("%s does not have any direct packages or includes", bundle.Name))
			}
		}
	}

	result.Ok(len(failures) == 0, "all bundle definitions complete")
	if len(failures) > 0 {
		result.Diagnostic("Incomplete bundles: \n" + strings.Join(failures, "\n"))
	}
}

var validBundleNameRegex = regexp.MustCompile(`^[A-Za-z0-9-_]+$`)

// checkBundleName validates all bundle names match the valid pattern and do
// not conflict with the MoM or full reserved names.
func checkBundleName(result *diva.Results, bundleInfo *pkginfo.BundleInfo) {
	var failures []string
	for _, bundle := range bundleInfo.BundleDefinitions {
		n := bundle.Name
		if !validBundleNameRegex.MatchString(n) || n == "MoM" || n == "full" {
			failures = append(failures, n)
		}
	}

	result.Ok(len(failures) == 0, "bundle names are valid")
	if len(failures) > 0 {
		result.Diagnostic("invalid bundle names:\n" + strings.Join(failures, "\n"))
	}
}

// checkBundleHeaderTitleMatchesFile checks that the file name of the bundle
// matches the bundle name in the header.
func checkBundleHeaderTitleMatchesFile(result *diva.Results, bundleInfo *pkginfo.BundleInfo) {
	var failures []string
	for _, bundle := range bundleInfo.BundleDefinitions {
		if bundle.Name != bundle.Header.Title {
			failures = append(failures, bundle.Name)
		}
	}
	result.Ok(len(failures) == 0, "'TITLE' headers match bundle file names")
	if len(failures) > 0 {
		result.Diagnostic("mismatched headers:\n" + strings.Join(failures, "\n"))
	}
}

// checkBundleRPMs checks that the RPMs for all bundles direct packages
// exist in the cached repo
func checkBundleRPMs(result *diva.Results, bundleInfo *pkginfo.BundleInfo, repo *pkginfo.Repo) {
	var err error
	var rpm *pkginfo.RPM
	var failures []string

	for _, bundle := range bundleInfo.BundleDefinitions {
		for pkg := range bundle.DirectPackages {
			rpm, err = pkginfo.GetRPM(repo, pkg)
			if rpm == nil || err != nil {
				failures = append(failures, fmt.Sprintf("%s from bundle %s", pkg, bundle.Name))
			}
		}
	}
	result.Ok(len(failures) == 0, "all packages found in repo")
	if len(failures) > 0 {
		result.Diagnostic("missing packages:\n" + strings.Join(failures, "\n"))
	}
}

// checkIfPundleDeletesExist determines whether a package bundle was removed
// since the latest bundle tag.
func checkIfPundleDeletesExist(result *diva.Results, tag string) error {
	var deleted []string
	var err error

	output, err := helpers.RunCommandOutput(
		"git", "-C", conf.Paths.BundleDefsRepo, "diff", tag+"..HEAD", "packages",
	)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(output)
	pattern := regexp.MustCompile(`^-[^-]`)
	for scanner.Scan() {
		matches := pattern.FindStringSubmatch(scanner.Text())
		if len(matches) > 0 {
			deleted = append(deleted, scanner.Text())
		}
	}
	result.Ok(len(deleted) == 0, "package bundles not deleted in release")
	if len(deleted) > 0 {
		result.Diagnostic("deleted package bundles:\n" + strings.Join(deleted, "\n"))
	}
	return nil
}

// checkIfBundleDeletesExist determines whether a bundle was removed
func checkIfBundleDeletesExist(result *diva.Results, tag string) error {
	var deleted []string
	var err error

	output, err := helpers.RunCommandOutput("git", "-C", conf.Paths.BundleDefsRepo,
		"log", "--diff-filter=D", tag+"..HEAD", "--summary")
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(output)
	pattern := regexp.MustCompile(`^\sdelete.*bundles/.*$`)
	for scanner.Scan() {
		// typically lines are formatted like: ' delete mode 100644 bundles/<bundleName'
		// ^\sdelete\smode\s[0-9]*\sbundles/.*$
		matches := pattern.FindStringSubmatch(scanner.Text())
		if len(matches) > 0 {
			s := strings.Split(scanner.Text(), "/")
			deleted = append(deleted, fmt.Sprintf("Bundle file deleted: %s", s[len(s)-1]))
		}
	}
	result.Ok(len(deleted) == 0, "bundles not deleted in release")
	if len(deleted) > 0 {
		result.Diagnostic("deleted bundle:\n" + strings.Join(deleted, "\n"))
	}
	return nil
}
