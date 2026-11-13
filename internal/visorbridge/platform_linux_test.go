//go:build linux

package visorbridge

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKernelPeerIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	uid, err := peerUID(server)
	if err != nil || uid != uint32(os.Geteuid()) {
		t.Fatal(uid, err)
	}
}
func TestOwnedExecutableAndConfigPaths(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "conductor")
	os.WriteFile(path, []byte("fixture"), 0700)
	if trustedExecutable(path) != nil {
		t.Fatal("owned executable refused")
	}
	os.Chmod(path, 0777)
	if trustedExecutable(path) == nil {
		t.Fatal("writable executable allowed")
	}
	os.Chmod(path, 0700)
	alias := filepath.Join(dir, "alias")
	os.Symlink(path, alias)
	if trustedExecutable(alias) == nil {
		t.Fatal("symlink executable allowed")
	}
}

func TestListenerDropsWrongKernelUIDBeforeHTTP(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is the trusted control peer")
	}
	path := filepath.Join(t.TempDir(), "refuse.sock")
	unix, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener := &peerListener{UnixListener: unix, uid: uint32(os.Geteuid()) + 1, slots: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { _, err := listener.Accept(); done <- err }()
	client, err := net.Dial("unix", path)
	if err != nil {
		unix.Close()
		t.Fatal(err)
	}
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [1]byte
	if _, err = client.Read(buffer[:]); err != io.EOF {
		t.Fatal("wrong peer not closed", err)
	}
	unix.Close()
	if <-done == nil {
		t.Fatal("unauthorized connection accepted")
	}
}
