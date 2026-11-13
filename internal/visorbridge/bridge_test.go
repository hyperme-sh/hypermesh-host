package visorbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
)

func fixture(t *testing.T) (*Bridge, []byte, *int, *int) {
	t.Helper()
	signs, reviews := 0, 0
	binding := Binding{"org/a/site/b", "owner", "sensor/read", "r1", strings.Repeat("a", 64), strings.Repeat("b", 64)}
	body, _ := json.Marshal(Call{binding, "12345678-1234-4234-8234-123456789abc", `{ "window": 10 }`})
	var proof []byte
	bridge := &Bridge{config: Config{ClientUID: 1001, Enabled: []Binding{binding}}, now: func() time.Time { return time.Unix(2000000000, 0) }, busy: make(chan struct{}, 8)}
	bridge.sign = func(ctx context.Context, call machineidentity.CapabilityCall) ([]byte, error) {
		signs++
		if string(call.Arguments) != `{ "window": 10 }` {
			t.Fatal("argument bytes changed")
		}
		proof = []byte(`{"call_id":"12345678-1234-4234-8234-123456789abc","expires_at":2000000020,"signature":"fixture"}`)
		return proof, nil
	}
	bridge.review = func(ctx context.Context, raw []byte) ([]byte, error) {
		reviews++
		if !bytes.Equal(raw, proof) {
			t.Fatal("machine proof replaced")
		}
		sum := sha256.Sum256([]byte("hypermesh-capability-review-v1\n" + `{"call_id":"12345678-1234-4234-8234-123456789abc","expires_at":2000000020}`))
		return json.Marshal(map[string]any{"protocol_version": 1, "call_id": "12345678-1234-4234-8234-123456789abc", "request_sha256": hex.EncodeToString(sum[:]), "decision": "allow", "expires_at": 2000000020})
	}
	return bridge, body, &signs, &reviews
}
func TestReviewPreservesBytesAndBindsDecision(t *testing.T) {
	bridge, raw, signs, reviews := fixture(t)
	result, err := bridge.Review(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if result.Decision != "allow" || result.CallSHA256 != hex.EncodeToString(sum[:]) || *signs != 1 || *reviews != 1 {
		t.Fatal(result)
	}
}
func TestDisabledOrChangedBindingsNeverSign(t *testing.T) {
	for _, mode := range []string{"disabled", "changed", "extra", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			bridge, raw, signs, reviews := fixture(t)
			switch mode {
			case "disabled":
				bridge.config.Enabled = nil
			case "changed":
				raw = bytes.Replace(raw, []byte("sensor/read"), []byte("sensor/write"), 1)
			case "extra":
				raw = append(raw[:len(raw)-1], []byte(`,"decision":"allow"}`)...)
			case "oversized":
				raw = bytes.Repeat([]byte("x"), 140001)
			}
			if _, err := bridge.Review(context.Background(), raw); err == nil || *signs != 0 || *reviews != 0 {
				t.Fatal("unlisted call signed")
			}
		})
	}
}
func TestReviewFailureOrMismatchedGrantNeverAllows(t *testing.T) {
	for _, mode := range []string{"signer", "service", "deny", "call", "digest", "expiry", "expired", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			bridge, raw, _, _ := fixture(t)
			original := bridge.review
			if mode == "signer" {
				bridge.sign = func(context.Context, machineidentity.CapabilityCall) ([]byte, error) {
					return nil, errors.New("private error")
				}
			}
			bridge.review = func(ctx context.Context, proof []byte) ([]byte, error) {
				if mode == "service" {
					return nil, errors.New("private error")
				}
				reply, err := original(ctx, proof)
				switch mode {
				case "deny":
					reply = bytes.Replace(reply, []byte("allow"), []byte("deny"), 1)
				case "call":
					reply = bytes.Replace(reply, []byte("12345678"), []byte("12345679"), 1)
				case "digest":
					var value map[string]any
					json.Unmarshal(reply, &value)
					value["request_sha256"] = strings.Repeat("0", 64)
					reply, _ = json.Marshal(value)
				case "expiry":
					reply = bytes.Replace(reply, []byte("2000000020"), []byte("2000000021"), 1)
				case "expired":
					bridge.now = func() time.Time { return time.Unix(2000000020, 0) }
				case "malformed":
					reply = []byte(`{"decision":"allow"}`)
				}
				return reply, err
			}
			if result, err := bridge.Review(context.Background(), raw); err == nil || result.Decision != "" {
				t.Fatal("invalid grant accepted")
			}
		})
	}
}
func TestPeerGateCannotBeSuppliedInHeaders(t *testing.T) {
	for _, uid := range []uint32{0, 1000, 1001} {
		bridge, raw, signs, _ := fixture(t)
		request := httptest.NewRequest("POST", "/review", bytes.NewReader(raw))
		request.Header.Set("X-UID", "1001")
		request = request.WithContext(context.WithValue(request.Context(), peerKey{}, uid))
		response := httptest.NewRecorder()
		bridge.Handler().ServeHTTP(response, request)
		if uid == 1001 {
			if response.Code != 200 || *signs != 1 {
				t.Fatal(response.Code)
			}
		} else if response.Code != 403 || *signs != 0 {
			t.Fatal("wrong UID authorized")
		}
	}
}
