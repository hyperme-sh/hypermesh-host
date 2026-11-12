package agent

import (
	"context"
	"strings"
	"testing"
)

func TestCertificationChannelKeepsModelHashAndCleanup(t *testing.T) {
	t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", `["example.invalid/selected-runtime"]`)
	a, job, calls := certFixture(t, 200)
	job.ImageDigest = "example.invalid/selected-runtime:test"
	result := a.runJob(context.Background(), job)
	if !result.Passed || !result.WorkloadVerified {
		t.Fatalf("configured channel refused: %+v", result)
	}
	if result.ImageHash == job.ImageDigest || result.ImageHash == "" {
		t.Fatalf("runtime reference replaced model hash: %+v", result)
	}
	if a.localLease() != nil {
		t.Fatal("certification activated a lease")
	}
	joined := ""
	for _, call := range *calls {
		joined += strings.Join(call, " ") + "\n"
	}
	if !strings.Contains(joined, "pull "+job.ImageDigest) || !strings.Contains(joined, "stop cert-container") {
		t.Fatalf("reference or cleanup lost: %s", joined)
	}
}
