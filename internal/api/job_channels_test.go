package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJobChannelOldAndNewShapes(t *testing.T) {
	t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", `["registry.test/runtime"]`)
	for _, field := range []string{"image_digest", "runtime_image"} {
		var job Job
		raw := `{"job_id":"job","kind":"lease_start","device_id":"host","` + field + `":"registry.test/runtime:test","optional_peer_patch":"0.1.1"}`
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			t.Fatal(err)
		}
		if job.ImageDigest != "registry.test/runtime:test" || job.JobID != "job" {
			t.Fatalf("roundtrip %+v", job)
		}
		encoded, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), `"runtime_image"`) || !strings.Contains(string(encoded), `"image_digest":"registry.test/runtime:test"`) {
			t.Fatalf("changed old wire shape %s", encoded)
		}
	}
	for _, raw := range []string{
		`{"runtime_image":"foreign.test/runtime:test"}`,
		`{"runtime_image":"registry.test/runtime:test","image_digest":"registry.test/runtime:test"}`,
		`{"runtime_image":null}`, `{"runtime_image":"registry.test/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
	} {
		var job Job
		if err := json.Unmarshal([]byte(raw), &job); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
