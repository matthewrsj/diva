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

package updatecontent

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/clearlinux/diva/diva"
	"github.com/clearlinux/diva/internal/config"
	"github.com/clearlinux/diva/internal/helpers"

	"github.com/clearlinux/mixer-tools/swupd"
)

// CheckManifestHashes compares manifest hashes against the hashes listed in
// the MoM for that version
func CheckManifestHashes(r *diva.Results, c *config.Config, version, minVer uint) error {
	cLoc := filepath.Join(c.Paths.CacheLocation, "update")
	momPath := filepath.Join(cLoc, fmt.Sprint(version), "Manifest.MoM")
	MoM, err := swupd.ParseManifestFile(momPath)
	if err != nil {
		return err
	}
	for i := range MoM.Files {
		if uint(MoM.Files[i].Version) < minVer {
			continue
		}
		mPath := filepath.Join(
			cLoc, fmt.Sprint(MoM.Files[i].Version), "Manifest."+MoM.Files[i].Name)
		hash, err := swupd.Hashcalc(mPath)
		if err != nil {
			return err
		}
		desc := fmt.Sprintf("Manifest.%s hash matches hash in MoM", MoM.Files[i].Name)
		r.Ok(hash == MoM.Files[i].Hash, desc)
	}

	return nil
}

func checkBundleFileHashes(cacheLoc string, m *swupd.Manifest, minVer uint) ([]string, error) {
	var wg sync.WaitGroup
	workers := len(m.Files)
	wg.Add(workers)
	fCh := make(chan *swupd.File)
	eCh := make(chan error, workers)
	fails := make(chan string, workers)

	cLoc := filepath.Join(cacheLoc, "update")
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for f := range fCh {
				if !f.Present() {
					continue
				}
				if uint(f.Version) < minVer {
					continue
				}
				fLoc := filepath.Join(cLoc, fmt.Sprint(f.Version), "files", f.Hash.String())
				hash, err := swupd.Hashcalc(fLoc)
				if err != nil {
					eCh <- err
					break
				}
				if hash != f.Hash {
					fails <- f.Name
				}
			}
		}()
	}

	var err error
	for _, f := range m.Files {
		select {
		case fCh <- f:
		case err = <-eCh:
			// break on first failure
			break
		}
	}
	close(fCh)
	wg.Wait()
	close(fails)

	if err == nil && len(eCh) > 0 {
		err = <-eCh
	}

	chanLen := len(eCh)
	for i := 0; i < chanLen; i++ {
		<-eCh
	}

	var failures []string
	for fail := range fails {
		failures = append(failures, fail)
	}

	return failures, err
}

// CheckFileHashes checks that the downloaded file content matches the hashes
// listed in the manifests
func CheckFileHashes(r *diva.Results, c *config.Config, version, minVer uint) error {
	cLoc := filepath.Join(c.Paths.CacheLocation, "update")
	momPath := filepath.Join(cLoc, fmt.Sprint(version), "Manifest.MoM")
	MoM, err := swupd.ParseManifestFile(momPath)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	nworkers := len(MoM.Files)
	wg.Add(nworkers)
	fChan := make(chan *swupd.File)
	errChan := make(chan error, nworkers)

	for i := 0; i < nworkers; i++ {
		go func() {
			defer wg.Done()
			for f := range fChan {
				if uint(f.Version) < minVer {
					continue
				}
				mPath := filepath.Join(cLoc, fmt.Sprint(f.Version), "Manifest."+f.Name)
				m, e := swupd.ParseManifestFile(mPath)
				if e != nil {
					errChan <- e
					break
				}
				failures, e := checkBundleFileHashes(c.Paths.CacheLocation, m, minVer)
				if e != nil {
					errChan <- e
					break
				}
				desc := fmt.Sprintf("file hashes for %s bundle match hashes in manifest", m.Name)
				r.Ok(len(failures) == 0, desc)
				if len(failures) > 0 {
					r.Diagnostic("mismatched hashes:\n" + strings.Join(failures, "\n"))
				}
			}
		}()
	}

	for i := range MoM.Files {
		fChan <- MoM.Files[i]
		select {
		case fChan <- MoM.Files[i]:
		case err = <-errChan:
			// break on first failure
			break
		}
	}
	close(fChan)
	wg.Wait()

	if err == nil && len(errChan) > 0 {
		err = <-errChan
	}

	return err
}

func checkBundleFileHashesPack(filesLoc string, m *swupd.Manifest, minVer uint) []error {
	var wg sync.WaitGroup
	workers := 4 // have to deal with "too many open files"
	wg.Add(workers)
	fCh := make(chan *swupd.File)
	eCh := make(chan error)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for f := range fCh {
				if uint(f.Version) < minVer {
					continue
				}
				if !f.Present() {
					continue
				}
				fLoc := filepath.Join(filesLoc, f.Hash.String())
				hash, err := swupd.Hashcalc(fLoc)
				if err != nil {
					eCh <- err
					continue
				}
				if hash != f.Hash {
					err := fmt.Errorf("%s hash did not match hash listed in %s for %s",
						fLoc, m.Name, f.Name)
					eCh <- err
					continue
				}
			}
		}()
	}

	for _, f := range m.Files {
		fCh <- f
	}
	close(fCh)
	wg.Wait()
	close(eCh)

	var errs []error
	for e := range eCh {
		errs = append(errs, e)
	}

	return errs
}

// CheckZeroPack validates the zero pack associated with the bundle at the present version
func CheckZeroPack(c *config.Config, m *swupd.Manifest) ([]string, error) {
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("check-zero-pack-%s-%d-", m.Name, m.Header.Version))
	if err != nil {
		return []string{}, err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	url := fmt.Sprintf("%s/update/%d/pack-%s-from-0.tar", c.UpstreamURL, m.Header.Version, m.Name)
	err = helpers.TarExtractURL(url, filepath.Join(tmpDir, fmt.Sprint(m.Header.Version)))
	if err != nil {
		return []string{}, err
	}

	var failures []string
	es := checkBundleFileHashesPack(filepath.Join(tmpDir, "staged"), m, 0)
	for _, e := range es {
		failures = append(failures, e.Error())
	}
	return failures, nil
}

func checkSingleDelta(deltaFile, fromFile, expHash string) error {
	testFile := fromFile + ".test"
	err := helpers.RunCommandSilent("bspatch", fromFile, testFile, deltaFile)
	if err != nil {
		return err
	}

	hash, err := swupd.Hashcalc(testFile)
	if err != nil {
		return err
	}

	if hash.String() != expHash {
		return fmt.Errorf("delta %s produced incorrect hash\nexpected: %s\nproduced: %s",
			deltaFile, expHash, hash.String())
	}

	return nil
}

func checkDeltaPack(c *config.Config, dir string, m *swupd.Manifest) error {
	deltaTos := make(map[string]uint32)
	for i := range m.Files {
		if m.Files[i].Version != m.Header.Version {
			continue
		}
		if !m.Files[i].Present() {
			continue
		}

		fLoc := filepath.Join(dir, "staged", m.Files[i].Hash.String())
		hash, err := swupd.Hashcalc(fLoc)
		if err != nil {
			// check for delta
			deltaTos[m.Files[i].Hash.String()] = m.Files[i].Version
			continue
		}
		if hash != m.Files[i].Hash {
			return fmt.Errorf("%s hash did not match hash listed in %s for %s",
				fLoc, m.Name, m.Files[i].Name)
		}
	}

	deltaNames := make(map[string]string)
	deltaFiles, err := ioutil.ReadDir(filepath.Join(dir, "delta"))
	if err != nil {
		return err
	}
	for _, d := range deltaFiles {
		// fromVer-toVer-fromHash-toHash
		fs := strings.Split(d.Name(), "-")
		if len(fs) != 4 {
			continue
		}
		deltaNames[fs[3]] = d.Name()
	}

	for h := range deltaTos {
		val, ok := deltaNames[h]
		if !ok {
			return fmt.Errorf("could not find %s in delta pack at %s", h, dir)
		}
		fields := strings.Split(filepath.Base(val), "-")
		// can expect that len(fields) == 4 due to above check
		fromV := fields[0]
		fromH := fields[2]
		url := fmt.Sprintf("%s/update/%s/files/%s.tar", c.UpstreamURL, fromV, fromH)
		fromF := filepath.Join(dir, fromH)
		err = helpers.TarExtractURL(url, fromF)
		if err != nil {
			return err
		}
		deltaFile := filepath.Join(dir, "delta", val)
		err = checkSingleDelta(deltaFile, fromF, h)
		if err != nil {
			return err
		}
	}
	return nil
}

// CheckDeltaPacks checks the delta packs for the m bundle
func CheckDeltaPacks(c *config.Config, m *swupd.Manifest) ([]string, error) {
	vers := make(map[uint32]struct{})
	var exists = struct{}{}
	for _, f := range m.Files {
		vers[f.Version] = exists
	}

	var wg sync.WaitGroup
	workers := len(vers)
	wg.Add(workers)
	vCh := make(chan uint32)
	errCh := make(chan error)
	failCh := make(chan string)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for v := range vCh {
				tmpDir, err := ioutil.TempDir("", fmt.Sprintf("check-delta-pack-%s-%d-", m.Name, v))
				if err != nil {
					errCh <- err
					break
				}
				defer func() {
					_ = os.RemoveAll(tmpDir)
				}()

				url := fmt.Sprintf("%s/update/%d/pack-%s-from-%d.tar", c.UpstreamURL, m.Header.Version, m.Name, v)
				err = helpers.TarExtractURL(url, filepath.Join(tmpDir, fmt.Sprint(v)))
				if err != nil {
					// assume no delta pack
					_ = os.RemoveAll(tmpDir)
					continue
				}

				err = checkDeltaPack(c, tmpDir, m)
				if err != nil {
					failCh <- err.Error()
					break
				}
			}
		}()
	}

	var err error
	for v := range vers {
		select {
		case vCh <- v:
		case err = <-errCh:
			// break on first failure
			break
		}
	}

	close(vCh)
	wg.Wait()
	close(errCh)
	close(failCh)

	if err == nil && len(errCh) > 0 {
		err = <-errCh
	}

	var fails []string
	for f := range failCh {
		fails = append(fails, f)
	}

	return fails, err
}

// CheckPacks validates the file contents of packs against manifest hashes
// using the pack check function pc
func CheckPacks(r *diva.Results, c *config.Config, version, minVer uint, delta bool) error {
	cLoc := filepath.Join(c.Paths.CacheLocation, "update")
	momPath := filepath.Join(cLoc, fmt.Sprint(version), "Manifest.MoM")
	MoM, err := swupd.ParseManifestFile(momPath)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	workers := 4
	wg.Add(workers)
	bCh := make(chan *swupd.File)
	eCh := make(chan error)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for man := range bCh {
				if uint(man.Version) < minVer {
					continue
				}
				mPath := filepath.Join(cLoc, fmt.Sprint(man.Version), "Manifest."+man.Name)
				m, e := swupd.ParseManifestFile(mPath)
				if e != nil {
					eCh <- e
					break
				}
				var failures []string
				var desc string
				if delta {
					failures, e = CheckDeltaPacks(c, m)
					desc = "delta pack content correct for " + m.Name
				} else {
					failures, e = CheckZeroPack(c, m)
					desc = "zero pack content correct for " + m.Name
				}

				if e != nil {
					eCh <- e
					break
				}
				r.Ok(len(failures) == 0, desc)
				if len(failures) > 0 {
					r.Diagnostic("pack issues:\n" + strings.Join(failures, "\n"))
				}
			}
		}()
	}

	for _, b := range MoM.Files {
		select {
		case bCh <- b:
		case err = <-eCh:
			// break on first failure
			break
		}
	}
	close(bCh)
	wg.Wait()
	close(eCh)

	if err == nil && len(eCh) > 0 {
		err = <-eCh
	}

	return err
}
