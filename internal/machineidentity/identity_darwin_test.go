//go:build darwin

package machineidentity

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinMachineIdentityFixedAlias(t *testing.T) {
	real, err := filepath.EvalSymlinks("/var")
	if err != nil {
		t.Fatal(err)
	}
	if got := identityPath(DefaultPath); got != real+strings.TrimPrefix(DefaultPath, "/var") {
		t.Fatal(got)
	}
	custom := "/private/tmp/custom-link/identity.json"
	if identityPath(custom) != custom {
		t.Fatal("custom symlink path must remain subject to ancestor checks")
	}
}
