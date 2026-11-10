package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRuntimeReceipt(t *testing.T) {
	const attempt = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	usage := `{"id":"chat-9","model":"m","usage":{"prompt_tokens":13,"completion_tokens":2}}`
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential sent to runtime")
		}
		w.Write([]byte(usage))
	}))
	defer runtime.Close()
	reports := 0
	plane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reports++
		if r.Method != "PUT" || r.URL.Path != "/api/v1/hypermesh/leases/lease/token-attempts/"+attempt+"/receipt" || r.Header.Get("Authorization") != "Bearer device" || r.Header.Get("X-Tenant-ID") != "tenant" {
			t.Error("wrong receipt identity")
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 5 || body["input_tokens"] != float64(13) || body["output_tokens"] != float64(2) || body["execution_id"] != "chat-9" || body["recipe"] != "recipe" || body["model"] != "m" {
			t.Error("wrong usage")
		}
	}))
	defer plane.Close()
	token := t.TempDir() + "/token"
	if err := os.WriteFile(token, []byte("device"), 0600); err != nil {
		t.Fatal(err)
	}
	h := host{runtime: runtime.URL, plane: plane.URL, key: "in", model: "m", recipe: "recipe", lease: "lease", tenant: "tenant", credentialFile: token, client: runtime.Client()}
	dispatch := func() int {
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
		r.Header.Set("Authorization", "Bearer in")
		r.Header.Set("X-Hypermesh-Token-Attempt", attempt)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if dispatch() != 200 || reports != 1 {
		t.Fatal("missing receipt")
	}
	usage = `{"id":"chat-10","model":"m"}`
	if dispatch() != 502 || reports != 1 {
		t.Fatal("missing usage treated as measured")
	}
}
