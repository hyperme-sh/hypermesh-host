// Package visorbundle installs explicitly requested, verified headless bundles.
// It never starts a process, changes services or enables host capabilities.
package visorbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/update"
)

const maxBundle = 256 << 20
const marker = ".hypermesh-visor-bundle.json"

type Download struct {
	URL  string `json:"url"`
	Size int64  `json:"size"`
}
type Bundle struct {
	Download
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema       int      `json:"schema"`
	Architecture string   `json:"architecture"`
	Bundle       Bundle   `json:"bundle"`
	Checksums    Download `json:"checksums"`
	Signature    Download `json:"signature"`
}
type installed struct {
	Schema       int    `json:"schema"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
}
type fetcher func(context.Context, string, int64) ([]byte, error)
type verifier func([]byte, []byte, []byte, []string) error

var files = map[string]os.FileMode{
	"usr/bin/hypermesh-visor-headless":                         0700,
	"usr/lib/hypermesh-visor-headless/conductor":               0700,
	"usr/share/doc/hypermesh-visor-headless/LICENSE":           0600,
	"usr/share/doc/hypermesh-visor-headless/conductor-LICENSE": 0600,
	"usr/share/doc/hypermesh-visor-headless/README.md":         0600,
}

func Decode(r io.Reader) (Manifest, error) {
	var m Manifest
	raw, err := io.ReadAll(io.LimitReader(r, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return m, errors.New("invalid bundle manifest size")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return m, errors.New("invalid bundle manifest")
	}
	if d.Decode(new(any)) != io.EOF {
		return m, errors.New("trailing manifest data")
	}
	return m, nil
}
func (m Manifest) validate(arch string) error {
	native := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[arch]
	if m.Schema != 1 || native == "" || m.Architecture != native || m.Bundle.Name != "hypermesh-visor-headless-"+native+".tar.gz" {
		return errors.New("bundle does not match this Linux host")
	}
	hash, err := hex.DecodeString(m.Bundle.SHA256)
	if err != nil || len(hash) != 32 || m.Bundle.SHA256 != strings.ToLower(m.Bundle.SHA256) {
		return errors.New("invalid bundle digest")
	}
	if m.Bundle.Size <= 0 || m.Bundle.Size > update.MaxDownloadBytes || m.Checksums.Size <= 0 || m.Checksums.Size > 1<<20 || m.Signature.Size <= 0 || m.Signature.Size > 1<<20 {
		return errors.New("invalid download bounds")
	}
	return nil
}

// Install uses the host updater's HTTPS and independently trusted GPG contract.
func Install(ctx context.Context, m Manifest, destination string, key []byte, fingerprints []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("headless bundle installation requires Linux")
	}
	return install(ctx, m, destination, key, fingerprints, runtime.GOARCH, func(ctx context.Context, u string, n int64) ([]byte, error) {
		return update.FetchLimited(ctx, nil, u, n)
	}, update.GPGVerify)
}
func install(ctx context.Context, m Manifest, destination string, key []byte, fingerprints []string, arch string, fetch fetcher, verify verifier) error {
	if err := m.validate(arch); err != nil {
		return err
	}
	if len(key) == 0 || len(fingerprints) == 0 {
		return errors.New("independent trusted key and fingerprints required")
	}
	dest, err := privateDestination(destination)
	if err != nil {
		return err
	}
	unlock, err := lockDestination(dest)
	if err != nil {
		return err
	}
	defer unlock()
	// Reserve the new directory exclusively; failed downloads leave no installation.
	if err = os.Mkdir(dest, 0700); err != nil {
		return errors.New("installation destination must not exist")
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dest)
		}
	}()
	sums, err := fetch(ctx, m.Checksums.URL, m.Checksums.Size)
	if err != nil {
		return errors.New("checksum download failed")
	}
	sig, err := fetch(ctx, m.Signature.URL, m.Signature.Size)
	if err != nil {
		return errors.New("signature download failed")
	}
	if err = verify(sums, sig, key, fingerprints); err != nil {
		return errors.New("bundle signature is not trusted")
	}
	payload, err := fetch(ctx, m.Bundle.URL, m.Bundle.Size)
	if err != nil {
		return errors.New("bundle download failed")
	}
	if err = update.CheckHash(sums, m.Bundle.Name, payload); err != nil {
		return errors.New("bundle checksum mismatch")
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != m.Bundle.SHA256 {
		return errors.New("requested bundle digest mismatch")
	}
	if err = unpack(ctx, payload, dest, m.Architecture); err != nil {
		return err
	}
	raw, _ := json.Marshal(installed{1, m.Architecture, m.Bundle.SHA256})
	if err = writeNew(filepath.Join(dest, marker), raw, 0600); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return errors.New("installation cancelled")
	}
	complete = true
	return nil
}
func privateDestination(destination string) (string, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || destination == "/" {
		return "", errors.New("absolute clean installation path required")
	}
	parent := filepath.Dir(destination)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return "", errors.New("installation parent must exist without symlinks")
	}
	st, err := os.Stat(parent)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || !owned(st) {
		return "", errors.New("installation parent must be owned by this user with mode 0700")
	}
	for dir := parent; ; dir = filepath.Dir(dir) {
		info, e := os.Stat(dir)
		if e != nil || !trustedOwner(info) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return "", errors.New("unsafe installation ancestor")
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	return destination, nil
}
func lockDestination(dest string) (func(), error) {
	name := filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+".visor-lock")
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("bundle operation locked; inspect any interrupted operation before removing its lock")
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(name)
		return nil, err
	}
	return func() { _ = os.Remove(name) }, nil
}
func unpack(ctx context.Context, payload []byte, dest, arch string) error {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return errors.New("invalid bundle archive")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		if ctx.Err() != nil {
			return errors.New("installation cancelled")
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count > 32 {
			return errors.New("invalid bundle archive")
		}
		name := strings.TrimPrefix(h.Name, "./")
		name = strings.TrimSuffix(name, "/")
		if name == "." || name == "" {
			if h.Typeflag == tar.TypeDir {
				continue
			}
			return errors.New("invalid archive root")
		}
		if path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
			return errors.New("unsafe archive path")
		}
		if h.Typeflag == tar.TypeDir {
			allowed := false
			for file := range files {
				if strings.HasPrefix(file, name+"/") {
					allowed = true
				}
			}
			if !allowed {
				return errors.New("unexpected archive directory")
			}
			continue
		}
		mode, ok := files[name]
		if !ok || seen[name] || h.Typeflag != tar.TypeReg || h.Linkname != "" || h.Size <= 0 || h.Size > 128<<20 {
			return errors.New("unexpected archive entry")
		}
		total += h.Size
		if total > maxBundle {
			return errors.New("expanded bundle exceeds limit")
		}
		if mode == 0600 && h.Size > 1<<20 {
			return errors.New("bundle document exceeds limit")
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return errors.New("truncated bundle entry")
		}
		if mode == 0700 {
			if err = checkELF(data, arch); err != nil {
				return err
			}
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err = writeNew(target, data, mode); err != nil {
			return err
		}
		seen[name] = true
	}
	if len(seen) != len(files) {
		return errors.New("incomplete headless bundle")
	}
	// Read through the gzip footer so checksum errors cannot be ignored after tar EOF.
	tail, err := io.ReadAll(io.LimitReader(gz, 10241))
	if err != nil || len(tail) > 10240 || len(bytes.Trim(tail, "\x00")) != 0 {
		return errors.New("invalid archive footer")
	}
	return nil
}
func checkELF(data []byte, arch string) error {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("bundle executable is not ELF")
	}
	defer f.Close()
	machine := elf.EM_X86_64
	if arch == "aarch64" {
		machine = elf.EM_AARCH64
	}
	if f.Class != elf.ELFCLASS64 || f.Machine != machine || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
		return errors.New("bundle executable architecture mismatch")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("headless bundle must be static")
		}
	}
	return nil
}
func writeNew(name string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Remove refuses unexpected files so it cannot erase runtime state or credentials.
func Remove(destination string) error {
	if runtime.GOOS != "linux" {
		return errors.New("headless bundle removal requires Linux")
	}
	dest, err := privateDestination(destination)
	if err != nil {
		return err
	}
	unlock, err := lockDestination(dest)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := os.Lstat(dest)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || !owned(st) {
		return errors.New("not a private bundle installation")
	}
	allowed := map[string]bool{marker: true}
	for name := range files {
		allowed[name] = true
	}
	err = filepath.WalkDir(dest, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dest {
			return nil
		}
		rel, _ := filepath.Rel(dest, p)
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil || !owned(info) || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe installation entry")
		}
		if d.IsDir() {
			for name := range files {
				if strings.HasPrefix(name, rel+"/") {
					return nil
				}
			}
			return errors.New("unexpected installation directory")
		}
		if !allowed[rel] || !info.Mode().IsRegular() {
			return errors.New("installation contains unmanaged state")
		}
		return nil
	})
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(dest, marker))
	if err != nil {
		return errors.New("missing installation marker")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	_ = f.Close()
	if err != nil || len(raw) > 4096 {
		return errors.New("invalid installation marker size")
	}
	var m installed
	if json.Unmarshal(raw, &m) != nil || m.Schema != 1 || (m.Architecture != "x86_64" && m.Architecture != "aarch64") || len(m.SHA256) != 64 {
		return errors.New("invalid installation marker")
	}
	if err = os.RemoveAll(dest); err != nil {
		return fmt.Errorf("remove bundle: %w", err)
	}
	return nil
}
