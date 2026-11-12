package hostregistration

import (
	"strings"
	"testing"
)

func TestChannelManifestRetainsModelAndScopeRequirements(t *testing.T) {
	t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", `["registry.test/runtime"]`)
	manifest := CertificationManifest{SuiteID: "pack-v1", CatalogID: "model", ClassID: "agx-large",
		FileHash: "sha256:" + strings.Repeat("a", 64), ImageDigest: "registry.test/runtime:test",
		SizeBytes: 12, Runtime: "nvidia", Backend: "cuda-jetson", ContextTokens: 4096, FullContext: true, DecodeTokS: 10}
	if err := manifest.validatePins(true); err != nil {
		t.Fatal(err)
	}
	manifest.FileHash = "registry.test/model:test"
	if err := manifest.validatePins(true); err == nil {
		t.Fatal("channel replaced model hash")
	}
	manifest.FileHash = "sha256:" + strings.Repeat("a", 64)
	manifest.ImageDigest = "foreign.test/runtime:test"
	if err := manifest.validatePins(true); err == nil {
		t.Fatal("unapproved runtime admitted")
	}
}
