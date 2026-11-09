//go:build darwin

package installer

import (
	"path/filepath"
	"testing"
)

func TestNativeDarwinFixedAliases(t *testing.T) {
	for _, prefix := range []string{"/var", "/etc"} {
		real, err := filepath.EvalSymlinks(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if got := macPath("", prefix+"/native-fixture/plan.json"); got != real+"/native-fixture/plan.json" {
			t.Fatal(got)
		}
	}
}
