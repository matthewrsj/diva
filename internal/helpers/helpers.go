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

package helpers

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Min returns the min of two strings...since go only implements Float64
func Min(a, b string) string {
	if a < b {
		return a
	}
	return b
}

// Max returns the max of two strings...since go only implements Float64
func Max(a, b string) string {
	if a > b {
		return a
	}
	return b
}

// CheckStatus does a simple http.Get on the url and performs a check against the
// error code. The response body is only returned for StatusOK
func CheckStatus(url string) (*http.Response, error) {
	resp, err := http.Get(url)
	if err != nil {
		return &http.Response{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Get %s replied: %d (%s)",
			url, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return resp, nil
}

// Download will attempt to download a from URL to the given filename. Does not
// try to extract the file, simply lays it on disk. Use this function if you
// know the file at url is not compressed or if you want to download a
// compressed file as-is.
func Download(url, filename string, overwrite bool) error {
	resp, err := CheckStatus(url)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// write to a temporary file so if the process is aborted the user is
	// not left with a truncated file
	tmpFile := filepath.Join(filepath.Dir(filename), ".dl."+filepath.Base(filename))
	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
		_ = os.Remove(tmpFile)
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	if overwrite {
		err := os.Remove(filename)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// move tempfile to final now that everything else has succeeded
	return RenameIfNotExists(tmpFile, filename)
}

// RenameIfNotExists moves src to dst if dst does not exist.
func RenameIfNotExists(src, dst string) error {
	err := os.Link(src, dst)
	if err != nil {
		if !os.IsExist(err) {
			return err
		}
	}

	return os.Remove(src)
}

// DownloadFile downloads from url and extracts the file if necessary using the
// compression method indicated by the url file extension. If there is no file
// extension or the extension does not match a supported compression method the
// file is downloaded as-is.
func DownloadFile(url, target string, overwrite bool) error {
	var err error
	switch filepath.Ext(url) {
	case ".gz":
		err = gzExtractURL(url, target, overwrite)
	case ".xz":
		err = xzExtractURL(url, target, overwrite)
	default:
		err = Download(url, target, overwrite)
	}
	return err
}

// gzExtractURL will download a file at the url and extract it to the target
// location
func gzExtractURL(url, target string, overwrite bool) error {
	resp, err := CheckStatus(url)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}

	if overwrite {
		err = os.RemoveAll(target)
		if err != nil {
			return err
		}
	}

	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	_, ioerr := io.Copy(out, zr)
	if ioerr != nil {
		if err := os.RemoveAll(target); err != nil {
			return errors.New(ioerr.Error() + err.Error())
		}
		return ioerr
	}

	return nil
}

func xzExtractURL(url, target string, overwrite bool) error {
	// download to file, no native xz compression library in Go
	if err := Download(url, target+".xz", overwrite); err != nil {
		return err
	}

	args := []string{"-T", "0", target + ".xz"}
	if overwrite {
		args = append([]string{"-f"}, args...)
	}

	return RunCommandSilent("unxz", args...)
}

// RunCommandSilent runs the given command with args and does not print output
func RunCommandSilent(cmdname string, args ...string) error {
	_, err := RunCommandOutput(cmdname, args...)
	return err
}

// RunCommandOutput executes the command with arguments and stores its output in
// memory. If the command succeeds returns that output, if it fails, return err that
// contains both the out and err streams from the execution.
func RunCommandOutput(cmdname string, args ...string) (*bytes.Buffer, error) {
	cmd := exec.Command(cmdname, args...)
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		var buf bytes.Buffer
		_, _ = fmt.Fprintf(&buf, ": failed to execute %s", strings.Join(cmd.Args, " "))
		if outBuf.Len() > 0 {
			_, _ = fmt.Fprintf(&buf, "\nSTDOUT:\n%s", outBuf.Bytes())
		}
		if errBuf.Len() > 0 {
			_, _ = fmt.Fprintf(&buf, "\nSTDERR:\n%s", errBuf.Bytes())
		}
		if outBuf.Len() > 0 || errBuf.Len() > 0 {
			// Finish without a newline to wrap well with the err.
			_, _ = fmt.Fprintf(&buf, "failed to execute")
		}
		return &outBuf, errors.New(err.Error() + buf.String())
	}
	return &outBuf, nil
}

// CheckoutRepoTag runs 'git checkout' for the specified tag
func CheckoutRepoTag(repoPath, tag string) error {
	return RunCommandSilent("git", "-C", repoPath, "checkout", "tags/"+tag)
}

// CheckoutBranch checkouts a branch of a repo
func CheckoutBranch(repoPath, branch string) error {
	return RunCommandSilent("git", "-C", repoPath, "checkout", branch)
}

// PullRepo runs 'git pull' in the repo at repoPath
func PullRepo(repoPath string) error {
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		return err
	}
	return RunCommandSilent("git", "-C", repoPath, "pull")
}

// CloneRepo runs 'git clone' of gitURL to the repoParent directory
func CloneRepo(gitURL, repoParent string) error {
	if err := os.MkdirAll(repoParent, 0755); err != nil {
		return err
	}
	return RunCommandSilent("git", "-C", repoParent, "clone", gitURL)
}

// TarExtractURL downloads a tar file from a URL and extracts it to target
func TarExtractURL(url, target string) error {
	err := os.MkdirAll(filepath.Dir(target), 0777)
	if err != nil {
		return err
	}
	if err = Download(url, target, false); err != nil {
		return err
	}

	return RunCommandSilent(
		"tar",
		"--preserve-permissions",
		"-C", filepath.Dir(target),
		"-xf", target,
	)
}

// PrintBegin prints the beginning of a task
func PrintBegin(message string, fmts ...interface{}) {
	_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf(fmt.Sprintf("--> %s", message), fmts...))
}

// PrintComplete prints completion of a task
func PrintComplete(message string, fmts ...interface{}) {
	_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf(fmt.Sprintf("    %s", message), fmts...))
}

// FailIfErr prints the error and exits the program with an error code if err
// is not nil
func FailIfErr(err error) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s: ERROR: %s\n", os.Args[0], err)
		os.Exit(1)
	}
}

// GetLatestVersion returns the version value at upstreamURL/latest or an error
// if unable to do so.
func GetLatestVersion(upstreamURL string) (string, error) {
	resp, err := http.Get(upstreamURL + "/latest")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.Trim(string(body), "\n"), nil
}

// GetLatestVersionUint is a wrapper for GetLatestVersion that converts the
// string output to a uint.
func GetLatestVersionUint(upstreamURL string) (uint, error) {
	versionString, err := GetLatestVersion(upstreamURL)
	if err != nil {
		return 0, err
	}
	ver, err := strconv.ParseUint(versionString, 10, 32)
	return uint(ver), err
}

// HashmapToSortedSlice converts a hashmap to a sorted slice
func HashmapToSortedSlice(hashmap map[string]bool) ([]string, error) {
	sorted := make([]string, 0, len(hashmap))
	for p := range hashmap {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	return sorted, nil
}
