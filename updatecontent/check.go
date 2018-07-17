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

	"github.com/clearlinux/diva/internal/config"
	"github.com/clearlinux/diva/internal/helpers"

	"github.com/clearlinux/mixer-tools/swupd"
)

// CheckManifestHashes compares manifest hashes against the hashes listed in
// the MoM for that version
func CheckManifestHashes(c *config.Config, version, minVer uint) (errs []error) {
	cLoc := filepath.Join(c.Paths.CacheLocation, "update")
	momPath := filepath.Join(cLoc, fmt.Sprint(version), "Manifest.MoM")
	MoM, err := swupd.ParseManifestFile(momPath)
	if err != nil {
		errs = append(errs, err)
		return
	}
	for i := range MoM.Files {
		if uint(MoM.Files[i].Version) < minVer {
			continue
		}
		mPath := filepath.Join(
			cLoc, fmt.Sprint(MoM.Files[i].Version), "Manifest."+MoM.Files[i].Name)
		hash, err := swupd.Hashcalc(mPath)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if hash != MoM.Files[i].Hash {
			err = fmt.Errorf("%s hash did not match hash listed in %s", mPath, momPath)
			errs = append(errs, err)
			continue
		}
	}
	return
}

func checkBundleFileHashes(cacheLoc string, m *swupd.Manifest, minVer uint) (errs []error) {
	var wg sync.WaitGroup
	workers := len(m.Files)
	wg.Add(workers)
	fCh := make(chan *swupd.File)
	eCh := make(chan error)

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
					continue
				}
				if hash != f.Hash {
					err = fmt.Errorf("%s hash did not match hash listed in %s for %s",
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

	for e := range eCh {
		errs = append(errs, e)
	}

	return
}

// CheckFileHashes checks that the downloaded file content matches the hashes
// listed in the manifests
func CheckFileHashes(c *config.Config, version, minVer uint) (errs []error) {
	cLoc := filepath.Join(c.Paths.CacheLocation, "update")
	momPath := filepath.Join(cLoc, fmt.Sprint(version), "Manifest.MoM")
	MoM, err := swupd.ParseManifestFile(momPath)
	if err != nil {
		errs = append(errs, err)
		return
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
				m, err := swupd.ParseManifestFile(mPath)
				if err != nil {
					errChan <- err
				}
				es := checkBundleFileHashes(c.Paths.CacheLocation, m, minVer)
				for _, e := range es {
					errChan <- e
				}
				if len(es) > 0 {
					continue
				}
			}
		}()
	}

	for i := range MoM.Files {
		fChan <- MoM.Files[i]
	}
	close(fChan)
	wg.Wait()
	close(errChan)
	for e := range errChan {
		errs = append(errs, e)
	}
	return
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
func CheckZeroPack(c *config.Config, m *swupd.Manifest) (errs []error) {
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("check-zero-pack-%s-%d-", m.Name, m.Header.Version))
	if err != nil {
		errs = append(errs, err)
		return
	}
	defer func() {
		if len(errs) == 0 {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	url := fmt.Sprintf("%s/update/%d/pack-%s-from-0.tar", c.UpstreamURL, m.Header.Version, m.Name)
	err = helpers.TarExtractURL(url, filepath.Join(tmpDir, fmt.Sprint(m.Header.Version)))
	if err != nil {
		errs = append(errs, err)
		return
	}

	es := checkBundleFileHashesPack(filepath.Join(tmpDir, "staged"), m, 0)
	for _, e := range es {
		errs = append(errs, e)
	}
	return
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
func CheckDeltaPacks(c *config.Config, m *swupd.Manifest) (errs []error) {
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

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for v := range vCh {
				tmpDir, err := ioutil.TempDir("", fmt.Sprintf("check-delta-pack-%s-%d-", m.Name, v))
				if err != nil {
					errCh <- err
					continue
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
					errCh <- err
					continue
				}
			}
		}()
	}

	for v := range vers {
		vCh <- v
	}

	close(vCh)
	wg.Wait()
	close(errCh)

	for e := range errCh {
		errs = append(errs, e)
	}

	return
}

// CheckPacks validates the file contents of packs against manifest hashes
// using the pack check function pc
func CheckPacks(c *config.Config, version, minVer uint, pc func(*config.Config, *swupd.Manifest) []error) (errs []error) {
	cLoc := filepath.Join(c.Paths.CacheLocation, "update")
	momPath := filepath.Join(cLoc, fmt.Sprint(version), "Manifest.MoM")
	MoM, err := swupd.ParseManifestFile(momPath)
	if err != nil {
		errs = append(errs, err)
		return
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
				m, err := swupd.ParseManifestFile(mPath)
				if err != nil {
					eCh <- err
					continue
				}
				es := pc(c, m)
				for _, e := range es {
					eCh <- e
				}
				if len(es) > 0 {
					continue
				}
			}
		}()
	}

	for _, b := range MoM.Files {
		bCh <- b
	}
	close(bCh)
	wg.Wait()
	close(eCh)

	for e := range eCh {
		errs = append(errs, e)
	}
	return
}
