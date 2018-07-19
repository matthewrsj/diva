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

package manifests

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/clearlinux/diva/diva"
	"github.com/clearlinux/diva/pkginfo"

	"github.com/clearlinux/mixer-tools/swupd"
)

type pkgDiff struct {
	new     []*pkginfo.File
	ch      []*pkginfo.File
	del     []*pkginfo.File
	removed bool
	added   bool
}

type manChanges struct {
	*swupd.Manifest

	changes map[string]pkgDiff
}

// CheckAll runs manifest assurance checks against the from and to versions
func CheckAll(
	r *diva.Results,
	cLoc string,
	mf, mt pkginfo.ManifestInfo,
	rf, rt *pkginfo.Repo,
) error {
	if err := getManifests(&mf, &mt); err != nil {
		return err
	}

	fromMans, toMans, err := getBundleFiles(cLoc, mf.MoM, mt.MoM)
	if err != nil {
		return err
	}

	for _, m := range toMans {
		m.BundleInfo.AllPackages, err = subtractedPackages(m, toMans)
		if err != nil {
			return err
		}
	}

	btc, err := getBundleChanges(cLoc, fromMans, toMans, rf, rt)
	if err != nil {
		return err
	}

	validateManifests(r, btc, mf.MoM.Header.Version)
	return nil
}

func getManifests(mf, mt *pkginfo.ManifestInfo) error {
	if err := pkginfo.PopulateManifests(mf); err != nil {
		return err
	}
	return pkginfo.PopulateManifests(mt)
}

func sortByName(fs []*pkginfo.File) []*pkginfo.File {
	newfs := make([]*pkginfo.File, len(fs))
	copy(newfs, fs)
	sort.Slice(newfs, func(i, j int) bool {
		return newfs[i].Name < newfs[j].Name
	})
	return newfs
}

func fileChanged(ff, tf *pkginfo.File) bool {
	return ((ff.Type != tf.Type) ||
		(ff.Permissions != tf.Permissions) ||
		(ff.Owner != tf.Owner) ||
		(ff.Group != tf.Group) ||
		(ff.SymlinkTarget != tf.SymlinkTarget) ||
		(ff.Hash != tf.Hash))
}

func diffOnePkg(fFiles, tFiles []*pkginfo.File) pkgDiff {
	pd := pkgDiff{}
	tidx, fidx := 0, 0
	tlen, flen := len(tFiles), len(fFiles)
	for tidx < tlen && fidx < flen {
		ff := fFiles[fidx]
		tf := tFiles[tidx]
		switch {
		case ff.Name < tf.Name: // file in fFiles not in tFiles
			pd.del = append(pd.del, ff)
			fidx++
			continue
		case ff.Name > tf.Name: // file in tFiles not in fFiles
			pd.new = append(pd.new, tf)
			tidx++
			continue
		case ff.Name == tf.Name: // file names match
			if fileChanged(ff, tf) {
				pd.ch = append(pd.ch, tf)
			}
			tidx++
			fidx++
		}
	}

	for ; tidx < tlen; tidx++ {
		pd.new = append(pd.new, tFiles[tidx])
	}

	for ; fidx < flen; fidx++ {
		pd.del = append(pd.del, fFiles[fidx])
	}

	return pd
}

func getMan(mf *swupd.File, cLoc string, bv uint32) (*swupd.Manifest, error) {
	mPath := filepath.Join(cLoc, fmt.Sprintf("update/%d/Manifest.%s", mf.Version, mf.Name))
	man, err := swupd.ParseManifestFile(mPath)
	if err != nil {
		return nil, err
	}
	// no bundle-info file for the index bundle
	if mf.Name == swupd.IndexBundle {
		return man, nil
	}
	biPath := filepath.Join(cLoc, fmt.Sprintf("update/%d/bundles/%s", bv, mf.Name))
	err = man.GetBundleInfo("", biPath)
	return man, err
}

func bundleFileWorker(
	wg *sync.WaitGroup,
	cLoc string,
	momFrom, momTo *swupd.Manifest,
	toCh <-chan *swupd.File,
	btCh, bfCh chan<- *swupd.Manifest,
	errCh chan<- error) {

	defer wg.Done()
	for to := range toCh {
		toMan, err := getMan(to, cLoc, momTo.Header.Version)
		if err != nil {
			errCh <- err
			break
		}
		btCh <- toMan

		var fr *swupd.File
		for _, from := range momFrom.Files {
			if from.Name != to.Name {
				continue
			}
			fr = from
			break
		}
		if fr == nil {
			errCh <- fmt.Errorf("unable to find %s in from MoM", to.Name)
			break
		}
		fromMan, err := getMan(fr, cLoc, momFrom.Header.Version)
		if err != nil {
			errCh <- err
			break
		}
		bfCh <- fromMan
	}
}

func getBundleFiles(cLoc string, momFrom, momTo *swupd.Manifest) ([]*swupd.Manifest, []*swupd.Manifest, error) {
	var wg sync.WaitGroup
	workers := len(momTo.Files)
	wg.Add(workers)
	toCh := make(chan *swupd.File)
	errCh := make(chan error, workers)
	btCh := make(chan *swupd.Manifest)
	bfCh := make(chan *swupd.Manifest)

	for i := 0; i < workers; i++ {
		go bundleFileWorker(&wg, cLoc, momFrom, momTo, toCh, btCh, bfCh, errCh)
	}

	var fromBundles []*swupd.Manifest
	var wg1 sync.WaitGroup
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		for m := range bfCh {
			fromBundles = append(fromBundles, m)
		}
	}()

	var toBundles []*swupd.Manifest
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		for m := range btCh {
			toBundles = append(toBundles, m)
		}
	}()

	var err error
	for _, to := range momTo.Files {
		select {
		case toCh <- to:
		case err = <-errCh:
			break
		}
	}
	close(toCh)
	wg.Wait()
	close(btCh)
	close(bfCh)
	wg1.Wait()
	if err == nil && len(errCh) > 0 {
		err = <-errCh
	}

	chanLen := len(errCh)
	for i := 0; i < chanLen; i++ {
		<-errCh
	}

	return fromBundles, toBundles, err
}

func newManChange(m *swupd.Manifest, r *pkginfo.Repo) (manChanges, error) {
	mch := manChanges{m, make(map[string]pkgDiff)}
	for p := range m.BundleInfo.AllPackages {
		n, err := pkginfo.GetFiles(r, p)
		if err != nil {
			return mch, err
		}
		mch.changes[p] = pkgDiff{new: n, added: true}
	}
	return mch, nil
}

func getManifestFromSlice(mans []*swupd.Manifest, name string) *swupd.Manifest {
	for i := range mans {
		if name == mans[i].Name {
			return mans[i]
		}
	}
	return nil
}

func diffManifests(from, to *swupd.Manifest, rf, rt *pkginfo.Repo) (manChanges, error) {
	mch := manChanges{to, make(map[string]pkgDiff)}
	for pt := range to.BundleInfo.AllPackages {
		newFiles, err := pkginfo.GetFiles(rt, pt)
		if err != nil {
			return mch, err
		}

		if _, ok := from.BundleInfo.AllPackages[pt]; !ok {
			mch.changes[pt] = pkgDiff{new: newFiles, added: true}
			continue
		}

		oldFiles, err := pkginfo.GetFiles(rf, pt)
		if err != nil {
			return mch, err
		}
		of := sortByName(oldFiles)
		nf := sortByName(newFiles)
		mch.changes[pt] = diffOnePkg(of, nf)
	}

	return mch, nil
}

func delManChange(m *swupd.Manifest, r *pkginfo.Repo) (manChanges, error) {
	mch := manChanges{m, make(map[string]pkgDiff)}
	for p := range m.BundleInfo.DirectPackages {
		n, err := pkginfo.GetFiles(r, p)
		if err != nil {
			return mch, err
		}
		mch.changes[p] = pkgDiff{del: n, removed: true}
	}
	return mch, nil
}

func deletedManifests(mch []manChanges, bf, bt []*swupd.Manifest, rf *pkginfo.Repo) ([]manChanges, error) {
	var err error
	for _, om := range bf {
		if nf := getManifestFromSlice(bt, om.Name); nf == nil {
			var old manChanges
			old, err = delManChange(om, rf)
			if err != nil {
				return mch, err
			}
			mch = append(mch, old)
		}
	}
	return mch, err
}

func getBundleChanges(cLoc string, bf, bt []*swupd.Manifest, rf, rt *pkginfo.Repo) ([]manChanges, error) {
	var wg sync.WaitGroup
	workers := len(bt)
	//workers = 1
	wg.Add(workers)
	inCh := make(chan *swupd.Manifest)
	outCh := make(chan manChanges)
	errCh := make(chan error, workers)
	fv, err := strconv.ParseUint(rf.Version, 10, 32)
	if err != nil {
		return []manChanges{}, err
	}
	sinceVer := uint32(fv)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for toMan := range inCh {
				if toMan.Header.Version <= sinceVer {
					continue
				}
				fromMan := getManifestFromSlice(bf, toMan.Name)
				if fromMan == nil {
					newm, e := newManChange(toMan, rf)
					if err != nil {
						errCh <- e
						break
					}
					outCh <- newm
				} else {
					ch, e := diffManifests(fromMan, toMan, rf, rt)
					if err != nil {
						errCh <- e
						break
					}
					outCh <- ch
				}
			}
		}()
	}

	var mch []manChanges
	var wg1 sync.WaitGroup
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		for ch := range outCh {
			mch = append(mch, ch)
		}
	}()

	for _, m := range bt {
		select {
		case inCh <- m:
		case err = <-errCh:
			break
		}
	}
	close(inCh)
	wg.Wait()
	close(outCh)
	wg1.Wait()

	if err == nil && len(errCh) > 0 {
		return mch, <-errCh
	}

	chanLen := len(errCh)
	for i := 0; i < chanLen; i++ {
		<-errCh
	}

	return deletedManifests(mch, bf, bt, rf)
}

func validateNew(chFiles []*pkginfo.File, mFiles []*swupd.File, sinceVer uint32, seen map[string]bool) []string {
	var errs []string
	for _, chf := range chFiles {
		i := sort.Search(len(mFiles), func(i int) bool {
			return chf.Name <= mFiles[i].Name
		})
		if i < len(mFiles) && mFiles[i].Name == chf.Name {
			mf := mFiles[i]
			seen[mf.Name] = true
			// found file
			if !mf.Present() {
				errs = append(errs, fmt.Sprintf("%s deleted", chf.Name))
				continue
			}
			if mf.Version <= sinceVer {
				errs = append(errs, fmt.Sprintf("%s changed before version %d (%d)", chf.Name, sinceVer, mf.Version))
				continue
			}
		} else {
			// error
			errs = append(errs, fmt.Sprintf("%s not found in manifest", chf.Name))
			continue
		}
	}
	return errs
}

func validateDel(delFiles []*pkginfo.File, mFiles []*swupd.File, sinceVer uint32, seen map[string]bool) []string {
	var errs []string
	for _, delf := range delFiles {
		i := sort.Search(len(mFiles), func(i int) bool {
			return delf.Name <= mFiles[i].Name
		})
		if i < len(mFiles) && mFiles[i].Name == delf.Name {
			mf := mFiles[i]
			seen[mf.Name] = true
			if mf.Present() {
				errs = append(errs, fmt.Sprintf("%s present (not deleted)", delf.Name))
				continue
			}
			if mf.Version <= sinceVer {
				errs = append(errs, fmt.Sprintf("%s deleted before version %d (%d)", delf.Name, sinceVer, mf.Version))
				continue
			}
		} else {
			errs = append(errs, fmt.Sprintf("%s not found in manifest", delf.Name))
			continue
		}
	}
	return errs
}

func handleErrSlice(r *diva.Results, errSlice []string, desc string) {
	errsPresent := len(errSlice) > 0
	r.Ok(!errsPresent, desc)
	if errsPresent {
		r.Diagnostic(strings.Join(errSlice, "\n"))
	}
}

func addExceptions(seen map[string]bool) {
	exc := []string{
		"/usr/lib/os-release",
		"/usr/share/clear/version",
		"/usr/share/clear/versionstamp",
	}
	for _, e := range exc {
		seen[e] = true
	}
}

func validateOne(r *diva.Results, b manChanges, sinceVer uint32) {
	bName := b.Manifest.Name
	if bName == swupd.IndexBundle {
		return
	}
	mFiles := b.Manifest.Files
	sort.Slice(mFiles, func(i, j int) bool {
		return mFiles[i].Name < mFiles[j].Name
	})
	seen := make(map[string]bool, len(mFiles))
	var errs []string
	for _, diff := range b.changes {
		if len(diff.ch) > 0 {
			errs = append(errs, validateNew(diff.ch, mFiles, sinceVer, seen)...)
		}
		if len(diff.new) > 0 {
			errs = append(errs, validateNew(diff.new, mFiles, sinceVer, seen)...)
		}
		if len(diff.del) > 0 {
			errs = append(errs, validateDel(diff.del, mFiles, sinceVer, seen)...)
		}
	}

	addExceptions(seen)

	for i := range mFiles {
		// only process files since the from version
		// do not process directories, because parent directories often
		// do not have their own records in RPMs
		if mFiles[i].Version <= sinceVer || mFiles[i].Type == swupd.TypeDirectory {
			continue
		}
		if _, ok := seen[mFiles[i].Name]; !ok {
			// TODO: REMOVE WHEN MANIFESTS RECORD FILE TYPE FOR DELETED FILES
			if !mFiles[i].Present() {
				continue
			}
			errs = append(errs,
				fmt.Sprintf("%s changed in manifest in version %d but not in RPM",
					mFiles[i].Name, mFiles[i].Version))
		}
	}

	handleErrSlice(r, errs, "files recorded correctly for "+bName)
}

func validateManifests(r *diva.Results, btc []manChanges, sinceVer uint32) {
	for _, b := range btc {
		validateOne(r, b, sinceVer)
	}
}

func resolveIncludes(includes map[string]*swupd.Manifest, m *swupd.Manifest, others []*swupd.Manifest) error {
	oscore := getManifestFromSlice(others, "os-core")
	if oscore == nil {
		return fmt.Errorf("unable to find include os-core for %s", m.Name)
	}
	includes[oscore.Name] = oscore

	for i := range m.BundleInfo.DirectIncludes {
		inc := getManifestFromSlice(others, m.BundleInfo.DirectIncludes[i])
		if inc == nil {
			return fmt.Errorf("unable to find include %s for %s",
				m.BundleInfo.DirectIncludes[i], m.Name)
		}
		includes[inc.Name] = inc
		if e := resolveIncludes(includes, inc, others); e != nil {
			return e
		}
	}
	return nil
}

func subtractedPackages(m *swupd.Manifest, others []*swupd.Manifest) (map[string]bool, error) {
	includes := make(map[string]*swupd.Manifest)
	err := resolveIncludes(includes, m, others)
	if err != nil {
		return nil, err
	}
	allPackages := make(map[string]bool)
	subbedPkgs := make(map[string]bool, len(m.BundleInfo.AllPackages))
	for k := range m.BundleInfo.AllPackages {
		subbedPkgs[k] = true
	}
	for _, incm := range includes {
		for p := range incm.BundleInfo.AllPackages {
			allPackages[p] = true
		}
	}
	for p := range allPackages {
		if _, ok := subbedPkgs[p]; ok {
			delete(subbedPkgs, p)
		}
	}
	return subbedPkgs, nil
}
