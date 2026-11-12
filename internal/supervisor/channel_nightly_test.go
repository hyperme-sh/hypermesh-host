//go:build nightly

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	hostruntime "github.com/FyberLabs/hypermesh-host/internal/runtime"
)

// This owner HTTP fixture stubs Docker; it does not qualify a physical runtime.
func TestHostChannelDispatchPreservesScopeAndRetry(t *testing.T) {
	t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", `["registry.test/runtime"]`)
	for _, field := range []string{"image_digest", "runtime_image"} {
		t.Run(field, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(api.HeaderTenantID) != "tenant" || r.Header.Get(api.HeaderAuthorization) != "Bearer hm_dev_fixture" || r.URL.Query().Get("device_id") != "host" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"job_id": "job", "device_id": "host", "kind": "lease_start", "lease_id": "lease", "catalog_id": "model", field: "registry.test/runtime:test", "optional_plane_patch": "0.1.2"})
			}))
			defer server.Close()
			client := api.NewClient(server.URL, "tenant")
			client.DeviceSecret = "hm_dev_fixture"
			first, err := client.PullJob(context.Background(), "host")
			if err != nil {
				t.Fatal(err)
			}
			retry, err := client.PullJob(context.Background(), "host")
			if err != nil {
				t.Fatal(err)
			}
			if first.JobID != retry.JobID || first.ImageDigest != retry.ImageDigest {
				t.Fatal("dispatch retry changed runtime binding")
			}
			fail := true
			runner := &hostruntime.NVIDIA{Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "pull" {
					if args[1] != first.ImageDigest {
						t.Fatal("reference changed")
					}
					if fail {
						return nil, errors.New("temporary registry failure")
					}
				}
				if args[0] == "run" {
					return []byte("owned-stub-container"), nil
				}
				return nil, nil
			}}
			spec := hostruntime.Spec{LeaseID: first.LeaseID, CatalogID: first.CatalogID, ImageDigest: first.ImageDigest}
			if _, err := runner.Start(context.Background(), spec); err == nil {
				t.Fatal("failed pull accepted")
			}
			fail = false
			handle, err := runner.Start(context.Background(), spec)
			if err != nil || handle.ImageDigest != first.ImageDigest {
				t.Fatalf("retry %v %v", handle, err)
			}
			client.TenantID = "other"
			if _, err := client.PullJob(context.Background(), "host"); err == nil {
				t.Fatal("foreign scope accepted")
			}
		})
	}
}
