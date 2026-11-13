package visorbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
)

func TestDecodeCapabilityCallPreservesArgumentBytes(t *testing.T) {
	var call machineidentity.CapabilityCall
	if err := decodeCall([]byte(`{"arguments":{ "window": 10 },"call_id":"example"}`), &call); err != nil {
		t.Fatal(err)
	}
	if string(call.Arguments) != `{ "window": 10 }` {
		t.Fatal("argument bytes changed")
	}
	for _, raw := range []string{`{"unknown":true}`, `{} {}`, `{"arguments":`} {
		if decodeCall([]byte(raw), &call) == nil {
			t.Fatal("invalid call accepted")
		}
	}
}

func TestSignCommandRequiresExistingEnrollment(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if Run(context.Background(), []string{"sign-call"}, &out, &diagnostic) != 2 {
		t.Fatal("missing context accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "call.json")
	raw, _ := json.Marshal(machineidentity.CapabilityCall{})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"sign-call", "--call", path, "--identity", filepath.Join(dir, "missing"), "--base", "https://example.test", "--tenant", "12345678-1234-4234-8234-123456789abc", "--device", "12345678-1234-4234-8234-123456789def"}
	out.Reset()
	diagnostic.Reset()
	if Run(context.Background(), args, &out, &diagnostic) != 1 || out.Len() != 0 || diagnostic.String() != "machine capability signing refused\n" {
		t.Fatal(out.String(), diagnostic.String())
	}
}
