package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageRecoveryDoesNotRepeatInference(t *testing.T) {
	const attempt = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	calls, reports := 0, 0
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"id":"execution","model":"m","usage":{"prompt_tokens":10,"completion_tokens":8,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":4}}}`))
	}))
	defer runtime.Close()
	accept := false
	var final map[string]any
	plane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reports++
		if r.Header.Get("Authorization") != "Bearer device-token" {
			t.Error("wrong credential")
		}
		json.NewDecoder(r.Body).Decode(&final)
		if !accept {
			w.WriteHeader(503)
		}
	}))
	defer plane.Close()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	os.WriteFile(token, []byte("device-token"), 0600)
	h := host{runtime: runtime.URL, plane: plane.URL, key: "ingress", model: "m", modelRevision: "sha256:artifact", usageDetails: true,
		recipe: "recipe", lease: "lease", tenant: "tenant", credentialFile: token, client: runtime.Client(), usageDir: filepath.Join(dir, "usage")}
	if err := h.prepareUsageStore(); err != nil {
		t.Fatal(err)
	}
	dispatch := func() int {
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"PRIVATE_PROMPT"}]}`))
		r.Header.Set("Authorization", "Bearer ingress")
		r.Header.Set("X-Hypermesh-Token-Attempt", attempt)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := dispatch(); got != 502 {
		t.Fatal(got)
	}
	if final["model_revision"] != "sha256:artifact" || final["cached_input_tokens"] != float64(3) || final["reasoning_tokens"] != float64(4) || final["output_tokens"] != float64(8) {
		t.Fatal(final)
	}
	raw, err := os.ReadFile(h.usagePath(attempt))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE_PROMPT", "device-token", "ingress"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private data persisted")
		}
	}
	accept = true
	if err := h.replayUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.replayUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := dispatch(); got != 409 || calls != 1 || reports != 2 {
		t.Fatal(got, calls, reports)
	}
	item, err := h.readUsage(attempt)
	if err != nil || item.State != "final" {
		t.Fatal(item, err)
	}
}

func TestUncertainUsageAndWrongScopeNeverRedispatch(t *testing.T) {
	h := host{usageDir: t.TempDir(), tenant: "tenant", lease: "lease", model: "m", recipe: "r"}
	const attempt = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if err := h.beginAttempt(attempt); err != nil {
		t.Fatal(err)
	}
	if err := h.beginAttempt(attempt); err == nil {
		t.Fatal("duplicate attempt accepted")
	}
	if err := h.replayUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.lease = "other"
	if err := h.replayUsage(context.Background()); err == nil {
		t.Fatal("scope mismatch accepted")
	}
}

func TestInvalidSubcountsLeaveAttemptUncertain(t *testing.T) {
	for _, details := range []string{
		`"prompt_tokens_details":{"cached_tokens":11}`,
		`"completion_tokens_details":{"reasoning_tokens":-1}`,
		`"completion_tokens_details":{"reasoning_tokens":9}`,
	} {
		t.Run(details, func(t *testing.T) {
			runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"id":"execution","model":"m","usage":{"prompt_tokens":10,"completion_tokens":8,` + details + `}}`))
			}))
			defer runtime.Close()
			reports := 0
			plane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reports++ }))
			defer plane.Close()
			dir := t.TempDir()
			token := filepath.Join(dir, "token")
			if err := os.WriteFile(token, []byte("device"), 0600); err != nil {
				t.Fatal(err)
			}
			h := host{runtime: runtime.URL, plane: plane.URL, key: "ingress", model: "m", usageDetails: true,
				credentialFile: token, client: runtime.Client(), usageDir: filepath.Join(dir, "usage")}
			if err := h.prepareUsageStore(); err != nil {
				t.Fatal(err)
			}
			const attempt = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
			r.Header.Set("Authorization", "Bearer ingress")
			r.Header.Set("X-Hypermesh-Token-Attempt", attempt)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			item, err := h.readUsage(attempt)
			if w.Code != 502 || reports != 0 || err != nil || item.State != "uncertain" {
				t.Fatal(w.Code, reports, item, err)
			}
		})
	}
}
