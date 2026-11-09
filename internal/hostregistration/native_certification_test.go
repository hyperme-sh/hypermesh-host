package hostregistration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNativeCertificationResponseBinding(t *testing.T) {
	for _, kind := range []string{"pass", "nonce", "tenant", "device", "runtime", "hardware", "protocol", "selling", "physical", "expiry", "changed-reference"} {
		t.Run(kind, func(t *testing.T) {
			r := fixture(t)
			r.ClassID = "darwin-arm64-lab"
			id, _ := NewRunID()
			m := NativeManifest{SuiteID: "pack-v1", CatalogID: "mac-model", ClassID: r.ClassID, Purpose: "native-certification-v1", Protocol: NativeMetalProtocol, FileHash: "sha256:" + strings.Repeat("a", 64), RuntimeSHA256: strings.Repeat("b", 64), CollectorCommit: strings.Repeat("d", 40), Device: "MTL0", EnvironmentHash: "sha256:" + strings.Repeat("e", 64), Hardware: strings.Repeat("f", 64), OS: "darwin", Arch: "arm64", Samples: 3, GeneratedTokens: 32, ContextTokens: 4096, DecodeTokS: 40, SizeBytes: 3}
			prior := NativeRun{Manifest: m, RunID: id, ManifestSHA256: strings.Repeat("c", 64)}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Header.Get("Authorization") != "Bearer hm_dev_"+strings.Repeat("s", 32) {
					t.Error("wrong credential")
				}
				if q.URL.Path != "/api/v1/hypermesh/agent/onboarding/native-certification/result" {
					t.Error(q.URL.Path)
				}
				var body map[string]any
				json.NewDecoder(q.Body).Decode(&body)
				result := NativeRun{ProtocolVersion: 1, Nonce: body["nonce"].(string), RunID: id, TenantID: testTenant, DeviceID: r.RequestID, RequestID: r.RequestID, Manifest: m, ManifestSHA256: prior.ManifestSHA256, State: "passed", ExpiresAt: time.Now().Add(time.Hour), SellingAllowed: flagValue(false)}
				switch kind {
				case "nonce":
					result.Nonce = "old"
				case "tenant":
					result.TenantID = id
				case "device":
					result.DeviceID = id
				case "runtime":
					result.Manifest.RuntimeSHA256 = strings.Repeat("a", 64)
				case "hardware":
					result.Manifest.Hardware = strings.Repeat("a", 64)
				case "protocol":
					result.Manifest.Protocol = "cuda-http"
				case "selling":
					result.SellingAllowed = flagValue(true)
				case "physical":
					result.Manifest.PhysicalAcceptance = true
				case "expiry":
					result.ExpiresAt = time.Time{}
				case "changed-reference":
					result.Manifest.DecodeTokS = 99
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			c, _ := New(server.URL, testTenant)
			c.http = server.Client()
			_, err := c.ReportNativeCertification(context.Background(), r, r.RequestID, "hm_dev_"+strings.Repeat("s", 32), prior, NativeEvidence{})
			if (err == nil) != (kind == "pass") {
				t.Fatal(kind, err)
			}
		})
	}
}
