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

package diva

import (
	"encoding/json"
	"io"

	"github.com/mndrix/tap-go" // tap
)

// Results holds the results of a test run
type Results struct {
	Name        string
	Description string
	Passed      uint
	Failed      uint
	*tap.T
}

// NewSuite returns a new *Results object
func NewSuite(name, desc string) *Results {
	return &Results{
		Name:        name,
		Description: desc,
		T:           tap.New(),
	}
}

// PrintJSON prints the Results in JSON format to the Writer provided.
func (r *Results) PrintJSON(w io.Writer) error {
	resOut, err := json.Marshal(r)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, string(resOut))
	return err
}

// Ok records a test pass or fail based on the test argument
func (r *Results) Ok(test bool, description string) {
	if test {
		r.Passed++
	} else {
		r.Failed++
	}
	r.T.Ok(test, description)
}
