//go:build linux || darwin

package machineidentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/tunnel"
)

func capabilityFixture(t *testing.T) (Provider, string, CapabilityCall, state) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	s := state{Schema: 1, Base: "https://example.test", Tenant: tenant, Device: device, Request: request, Authority: "local", Plane: "local", Bound: true, Key: key}
	p := Provider{Path: filepath.Join(dir, "identity.json"), Now: func() time.Time { return time.Unix(2000000000, 0) }}
	if err = save(p.Path, s); err != nil {
		t.Fatal(err)
	}
	wg, _, err := tunnel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wgPath := filepath.Join(dir, "wireguard.key")
	if err = os.WriteFile(wgPath, []byte(wg+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	call := CapabilityCall{Scope: "org/a/site/b", Owner: "owner", ID: "sensor/read", Revision: "v1", SourceSHA256: strings.Repeat("a", 64), GraphSHA256: strings.Repeat("b", 64), CallID: request, Arguments: json.RawMessage(`{ "window": 10 }`)}
	return p, wgPath, call, s
}

func TestCapabilitySignatureUsesExistingIdentityAndExactArguments(t *testing.T) {
	p, wg, call, s := capabilityFixture(t)
	before, _ := os.ReadFile(p.Path)
	wgBefore, _ := os.ReadFile(wg)
	raw, err := p.SignCapability(context.Background(), s.Base, tenant, device, wg, call)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid output")
	}
	sig, _ := base64.StdEncoding.DecodeString(result["signature"].(string))
	delete(result, "signature")
	canonical, _ := json.Marshal(result)
	publicKey, _ := base64.StdEncoding.DecodeString(public(s.Key))
	if !ed25519.Verify(publicKey, append([]byte("hypermesh-capability-review-v1\n"), canonical...), sig) {
		t.Fatal("signature mismatch")
	}
	hash := sha256.Sum256(call.Arguments)
	if result["arguments_sha256"] != hex.EncodeToString(hash[:]) || result["tenant_id"] != tenant || result["device_id"] != device || result["request_id"] != request || result["expires_at"] != float64(2000000020) {
		t.Fatal("binding mismatch")
	}
	wgPublic, _ := tunnel.PublicFromPrivate(string(wgBefore))
	if result["wireguard_public_key"] != wgPublic {
		t.Fatal("wrong WireGuard key")
	}
	after, _ := os.ReadFile(p.Path)
	wgAfter, _ := os.ReadFile(wg)
	if !bytes.Equal(before, after) || !bytes.Equal(wgBefore, wgAfter) || bytes.Contains(raw, []byte(s.Key)) || bytes.Contains(raw, bytes.TrimSpace(wgBefore)) {
		t.Fatal("key state changed or disclosed")
	}
	again, err := p.SignCapability(context.Background(), s.Base, tenant, device, wg, call)
	if err != nil {
		t.Fatal(err)
	}
	var next map[string]any
	json.Unmarshal(again, &next)
	if result["nonce"] == next["nonce"] {
		t.Fatal("nonce reused")
	}
}

func TestCapabilitySigningRefusesUnsafeOrInactiveState(t *testing.T) {
	for _, mode := range []string{"missing", "unbound", "pending", "tenant", "device", "base", "authority", "wg-missing", "wg-mode", "wg-symlink", "cancelled", "arguments", "call-id"} {
		t.Run(mode, func(t *testing.T) {
			p, wg, call, s := capabilityFixture(t)
			ctx := context.Background()
			base := s.Base
			tenantID := tenant
			deviceID := device
			switch mode {
			case "missing":
				os.Remove(p.Path)
			case "unbound":
				s.Bound = false
				save(p.Path, s)
			case "pending":
				s.Pending = s.Key
				save(p.Path, s)
			case "tenant":
				tenantID = device
			case "device":
				deviceID = tenant
			case "base":
				base = "https://other.test"
			case "authority":
				p.Authority = "other"
			case "wg-missing":
				os.Remove(wg)
			case "wg-mode":
				os.Chmod(wg, 0644)
			case "wg-symlink":
				os.Rename(wg, wg+".real")
				os.Symlink(wg+".real", wg)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "arguments":
				call.Arguments = json.RawMessage(`[]`)
			case "call-id":
				call.CallID = "invalid"
			}
			raw, err := p.SignCapability(ctx, base, tenantID, deviceID, wg, call)
			if err == nil || len(raw) != 0 {
				t.Fatal("unsafe signing allowed")
			}
			if mode == "missing" {
				if _, err = os.Stat(p.Path); !os.IsNotExist(err) {
					t.Fatal("identity recreated")
				}
			}
			if mode == "wg-missing" {
				if _, err = os.Stat(wg); !os.IsNotExist(err) {
					t.Fatal("WireGuard key recreated")
				}
			}
		})
	}
}
