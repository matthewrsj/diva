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

import "github.com/spf13/cobra"

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Run various content and metadata checks",
	Long:  `Run various checks against distribution content or metadata`,
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.AddCommand(bloatCheckCmd)
	checkCmd.AddCommand(chirpCmd)
	checkCmd.AddCommand(debuginfoCmd)
	checkCmd.AddCommand(pyDepsCmd)
	checkCmd.AddCommand(ucCmd)
	checkCmd.AddCommand(verifyBundlesCmd)
	checkCmd.AddCommand(rpmFileConflictsCmd)
	checkCmd.AddCommand(sigCmd)
	checkCmd.AddCommand(verifyManCmd)
}
