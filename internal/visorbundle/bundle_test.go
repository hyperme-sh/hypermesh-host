package visorbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/FyberLabs/hypermesh-host/internal/update"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func binaryFixture(machine uint16) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	return b
}
func archiveFixture(t *testing.T, change func(string, *tar.Header, []byte) (*tar.Header, []byte)) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, mode := range files {
		data := []byte("fixture document")
		if mode == 0700 {
			data = binaryFixture(62)
		}
		h := &tar.Header{Name: "./" + name, Mode: int64(mode), Size: int64(len(data)), Typeflag: tar.TypeReg}
		if change != nil {
			h, data = change(name, h, data)
		}
		if h == nil {
			continue
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func manifestFixture(payload []byte) (Manifest, fetcher) {
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	name := "hypermesh-visor-headless-x86_64.tar.gz"
	sums := []byte(fmt.Sprintf("%s  %s\n", hash, name))
	sig := []byte("fixture signature")
	m := Manifest{Schema: 1, Architecture: "x86_64", Bundle: Bundle{Download: Download{"https://fixture/bundle?secret=token", int64(len(payload))}, Name: name, SHA256: hash}, Checksums: Download{"https://fixture/sums", int64(len(sums))}, Signature: Download{"https://fixture/signature", int64(len(sig))}}
	fetch := func(ctx context.Context, u string, size int64) ([]byte, error) {
		switch u {
		case m.Bundle.URL:
			return payload, nil
		case m.Checksums.URL:
			return sums, nil
		case m.Signature.URL:
			return sig, nil
		}
		return nil, errors.New("unexpected URL")
	}
	return m, fetch
}
func accepted([]byte, []byte, []byte, []string) error { return nil }
func installFixture(t *testing.T, payload []byte, verify verifier) (string, error) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(parent, "visor")
	m, f := manifestFixture(payload)
	return dest, install(context.Background(), m, dest, []byte("fixture key"), []string{"fixture fingerprint"}, "amd64", f, verify)
}
func TestInstallAndRemoveOnlyBundle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux bundle installer")
	}
	dest, err := installFixture(t, archiveFixture(t, nil), accepted)
	if err != nil {
		t.Fatal(err)
	}
	for name, mode := range files {
		st, err := os.Stat(filepath.Join(dest, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("file %s: %v", name, err)
		}
	}
	unrelated := filepath.Join(filepath.Dir(dest), "owner-state")
	if err = os.WriteFile(unrelated, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Remove(dest); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("bundle remains")
	}
	if data, _ := os.ReadFile(unrelated); string(data) != "keep" {
		t.Fatal("owner state changed")
	}
}
func TestRefusesUnsafeOrIncompleteArchives(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux bundle installer")
	}
	for _, kind := range []string{"traversal", "absolute", "symlink", "hardlink", "unknown", "missing", "wrong-arch", "dynamic", "corrupt-footer"} {
		t.Run(kind, func(t *testing.T) {
			payload := archiveFixture(t, func(name string, h *tar.Header, data []byte) (*tar.Header, []byte) {
				if name != "usr/bin/hypermesh-visor-headless" {
					return h, data
				}
				switch kind {
				case "traversal":
					h.Name = "../escape"
				case "absolute":
					h.Name = "/escape"
				case "symlink":
					h.Typeflag = tar.TypeSymlink
					h.Linkname = "/escape"
					data = nil
				case "hardlink":
					h.Typeflag = tar.TypeLink
					h.Linkname = "/escape"
					data = nil
				case "unknown":
					h.Name = "usr/bin/unrelated"
				case "missing":
					return nil, nil
				case "wrong-arch":
					data = binaryFixture(183)
				case "dynamic":
					data = []byte("not an ELF binary")
				}
				h.Size = int64(len(data))
				return h, data
			})
			if kind == "corrupt-footer" {
				payload[len(payload)-8] ^= 1
			}
			dest, err := installFixture(t, payload, accepted)
			if err == nil {
				t.Fatal("unsafe bundle accepted")
			}
			if _, err = os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("failed install left files")
			}
		})
	}
}
func TestVerificationPrecedesExtractionAndRedactsURLs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux bundle installer")
	}
	payload := archiveFixture(t, nil)
	m, fetch := manifestFixture(payload)
	for _, kind := range []string{"signature", "digest", "download", "cancelled", "wrong-host", "existing"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			_ = os.Chmod(parent, 0700)
			dest := filepath.Join(parent, "visor")
			candidate := m
			f := fetch
			v := accepted
			ctx := context.Background()
			switch kind {
			case "signature":
				v = func([]byte, []byte, []byte, []string) error { return errors.New("bad signature") }
			case "digest":
				candidate.Bundle.SHA256 = strings.Repeat("0", 64)
			case "download":
				f = func(context.Context, string, int64) ([]byte, error) {
					return nil, errors.New("https://fixture/?secret=token")
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "wrong-host":
				candidate.Architecture = "aarch64"
			case "existing":
				_ = os.Mkdir(dest, 0700)
				_ = os.WriteFile(filepath.Join(dest, "keep"), []byte("keep"), 0600)
			}
			err := install(ctx, candidate, dest, []byte("key"), []string{"fingerprint"}, "amd64", f, v)
			if err == nil {
				t.Fatal("invalid install accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token") {
				t.Fatal("URL credential exposed")
			}
			if kind == "existing" {
				if data, _ := os.ReadFile(filepath.Join(dest, "keep")); string(data) != "keep" {
					t.Fatal("existing directory modified")
				}
			} else if _, err = os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("failed install remains")
			}
		})
	}
}
func TestRemovePreservesUnmanagedState(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux bundle installer")
	}
	for _, kind := range []string{"state", "symlink", "marker"} {
		t.Run(kind, func(t *testing.T) {
			dest, err := installFixture(t, archiveFixture(t, nil), accepted)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "state":
				_ = os.WriteFile(filepath.Join(dest, "credentials.json"), []byte("keep"), 0600)
			case "symlink":
				_ = os.Symlink("/tmp", filepath.Join(dest, "foreign"))
			case "marker":
				_ = os.Remove(filepath.Join(dest, marker))
			}
			if Remove(dest) == nil {
				t.Fatal("unsafe removal accepted")
			}
			if _, err = os.Stat(filepath.Join(dest, "usr/bin/hypermesh-visor-headless")); err != nil {
				t.Fatal("bundle altered on refusal")
			}
		})
	}
}
func TestPrivateParentAndCLI(t *testing.T) {
	parent := t.TempDir()
	_ = os.Chmod(parent, 0755)
	if _, err := privateDestination(filepath.Join(parent, "visor")); err == nil {
		t.Fatal("public parent accepted")
	}
	if _, err := privateDestination("relative"); err == nil {
		t.Fatal("relative path accepted")
	}
	var out, diag bytes.Buffer
	for _, args := range [][]string{nil, {"start"}, {"install"}, {"install", "--directory", filepath.Join(parent, "visor")}, {"remove", "--directory", filepath.Join(parent, "visor"), "extra"}} {
		if Run(context.Background(), args, &out, &diag) != 2 {
			t.Fatalf("bad arguments accepted: %v", args)
		}
	}
	if Run(context.Background(), []string{"install", "--help"}, &out, &diag) != 0 {
		t.Fatal("help failed")
	}
}

func TestExclusiveOperationAndParentSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux bundle installer")
	}
	parent := t.TempDir()
	_ = os.Chmod(parent, 0700)
	dest := filepath.Join(parent, "visor")
	unlock, err := lockDestination(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	m, f := manifestFixture(archiveFixture(t, nil))
	if install(context.Background(), m, dest, []byte("key"), []string{"fp"}, "amd64", f, accepted) == nil {
		t.Fatal("concurrent install accepted")
	}
	if _, err = os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("locked install created destination")
	}
	link := filepath.Join(parent, "linked")
	if err = os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if _, err = privateDestination(filepath.Join(link, "visor")); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestSignatureRefusalDoesNotDownloadPayload(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux bundle installer")
	}
	parent := t.TempDir()
	_ = os.Chmod(parent, 0700)
	m, f := manifestFixture(archiveFixture(t, nil))
	downloaded := false
	fetch := func(ctx context.Context, u string, n int64) ([]byte, error) {
		if u == m.Bundle.URL {
			downloaded = true
		}
		return f(ctx, u, n)
	}
	err := install(context.Background(), m, filepath.Join(parent, "visor"), []byte("key"), []string{"fp"}, "amd64", fetch, func([]byte, []byte, []byte, []string) error { return errors.New("denied") })
	if err == nil || downloaded {
		t.Fatal("untrusted signature reached payload download")
	}
}

func TestManifestUsesProductionDownloadLimit(t *testing.T) {
	m, _ := manifestFixture([]byte("fixture"))
	m.Bundle.Size = update.MaxDownloadBytes
	if err := m.validate("amd64"); err != nil {
		t.Fatalf("download boundary rejected: %v", err)
	}
	m.Bundle.Size++
	if err := m.validate("amd64"); err == nil {
		t.Fatal("manifest exceeds production download limit")
	}
}
