package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestServiceChannelSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/service-reference-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		VectorsSHA256 string `json:"vectors_sha256"`
	}
	metadata, err := os.ReadFile("testdata/service-channels-source.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(metadata, &source); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != source.VectorsSHA256 {
		t.Fatal("shared vectors differ from recorded source")
	}
	var vectors struct {
		Repository         string
		Accepted, Rejected []string
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, value := range vectors.Accepted {
		if ref, err := ServiceImageRef(value, vectors.Repository); err != nil || ref != value {
			t.Fatalf("accepted %q: %q %v", value, ref, err)
		}
	}
	for _, value := range vectors.Rejected {
		if _, err := ServiceImageRef(value, vectors.Repository); err == nil {
			t.Fatalf("accepted rejected reference %q", value)
		}
	}
	for _, repository := range []string{"registry.test:0/runtime", "registry.test:65536/runtime", "UPPER.test/runtime"} {
		if _, err := ServiceImageRef(repository+":test", repository); err == nil {
			t.Fatalf("invalid policy %q", repository)
		}
	}
}

func TestChannelPolicyPreservesReferenceAndRejectsForeignRegistry(t *testing.T) {
	t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", `["registry.test/runtime"]`)
	ref := "registry.test/runtime:test"
	if got, err := ImageRef(ref); err != nil || got != ref {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	for _, value := range []string{"foreign.test/runtime:test", ref + "\n", "registry.test/runtime"} {
		if _, err := ImageRef(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	for _, policy := range []string{`[]`, `["registry.test/runtime", "bad"]`, `["registry.test/runtime", "registry.test/runtime"]`} {
		t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", policy)
		if _, err := ChannelRef(ref); err == nil {
			t.Fatalf("accepted policy %s", policy)
		}
	}
}

func TestChannelPullFailureDoesNotUseStaleCache(t *testing.T) {
	t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", `["registry.test/runtime"]`)
	for _, backend := range []string{"nvidia", "hip"} {
		calls := []string{}
		run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			if args[0] == "pull" {
				return nil, errors.New("registry unavailable")
			}
			return []byte("cached-image"), nil
		}
		spec := Spec{LeaseID: "lease", CatalogID: "model", ImageDigest: "registry.test/runtime:test"}
		var err error
		if backend == "nvidia" {
			_, err = (&NVIDIA{Run: run}).Start(context.Background(), spec)
		} else {
			_, err = (&HIP{Run: run}).Start(context.Background(), spec)
		}
		if err == nil || len(calls) != 1 || calls[0] != "pull "+spec.ImageDigest {
			t.Fatalf("%s used stale image: %v %v", backend, calls, err)
		}
	}
}
