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
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"

	"github.com/clearlinux/diva/internal/config"
	"github.com/clearlinux/diva/internal/helpers"

	"github.com/clearlinux/mixer-tools/swupd"
)

// CheckManifestHashes compares manifest hashes against the hashes listed in
// the MoM for that version
func CheckManifestHashes(cacheLoc string, version, minVer uint) error {
	cLoc := filepath.Join(cacheLoc, "update")
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
		if hash != MoM.Files[i].Hash {
			return fmt.Errorf("%s hash did not match hash listed in %s", mPath, momPath)
		}
	}
	return nil
}

func checkBundleFileHashes(cacheLoc string, m *swupd.Manifest, minVer uint) error {
	cLoc := filepath.Join(cacheLoc, "update")
	for i := range m.Files {
		if !m.Files[i].Present() {
			continue
		}
		if uint(m.Files[i].Version) < minVer {
			continue
		}
		fLoc := filepath.Join(
			cLoc, fmt.Sprint(m.Files[i].Version), "files", m.Files[i].Hash.String())
		hash, err := swupd.Hashcalc(fLoc)
		if err != nil {
			return err
		}
		if hash != m.Files[i].Hash {
			return fmt.Errorf("%s hash did not match hash listed in %s for %s",
				fLoc, m.Name, m.Files[i].Name)
		}
	}

	return nil
}

// CheckFileHashes checks that the downloaded file content matches the hashes
// listed in the manifests
func CheckFileHashes(cacheLoc string, version, minVer uint) error {
	cLoc := filepath.Join(cacheLoc, "update")
	momPath := filepath.Join(cLoc, fmt.Sprint(version), "Manifest.MoM")
	MoM, err := swupd.ParseManifestFile(momPath)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	nworkers := len(MoM.Files)
	wg.Add(nworkers)
	fChan := make(chan *swupd.File)
	errChan := make(chan error)

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
				err = checkBundleFileHashes(cacheLoc, m, minVer)
				if err != nil {
					errChan <- err
				}
			}
		}()
	}

	for i := range MoM.Files {
		fChan <- MoM.Files[i]
	}
	close(fChan)
	wg.Wait()
	var errs []string
	if len(errChan) > 0 {
		for e := range errChan {
			errs = append(errs, e.Error())
		}
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

func checkBundleFileHashesPack(filesLoc string, m *swupd.Manifest, minVer uint) error {
	for i := range m.Files {
		if uint(m.Files[i].Version) < minVer {
			continue
		}
		fLoc := filepath.Join(filesLoc, m.Files[i].Hash.String())
		hash, err := swupd.Hashcalc(fLoc)
		if err != nil {
			return err
		}
		if hash != m.Files[i].Hash {
			return fmt.Errorf("%s hash did not match hash listed in %s for %s",
				fLoc, m.Name, m.Files[i].Name)
		}
	}

	return nil
}

func checkZeroPack(c *config.Config, m *swupd.Manifest) error {
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("check-zero-pack-%s-%d", m.Name, m.Header.Version))
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/update/%d/pack-%s-from-0.tar", c.UpstreamURL, m.Header.Version, m.Name)
	err = helpers.TarExtractURL(url, tmpDir)
	if err != nil {
		return err
	}

	return checkBundleFileHashesPack(filepath.Join(tmpDir, "files"), m, 0)
}

// CheckZeroPacks validates the file contents of zero packs against manifest
// hashes.
func CheckZeroPacks(c *config.Config, version, minVer uint) error {
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
		m, err := swupd.ParseManifestFile(mPath)
		if err != nil {
			return err
		}
		err = checkZeroPack(c, m)
		if err != nil {
			return nil
		}
	}

	return nil
}
