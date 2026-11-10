// Command hypermesh-receipt-host fronts one operator-bound local chat runtime.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var uuid = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
var digest = regexp.MustCompile("^[0-9a-f]{64}$")

type host struct {
	tokenizer                                                         string
	plane, runtime, tenant, lease, recipe, model, key, credentialFile string
	client                                                            *http.Client
}

func bounded(r io.Reader) ([]byte, error) {
	const limit = 16 << 20
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if len(b) > limit {
		return nil, errors.New("payload too large")
	}
	return b, e
}
func (h host) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || (r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/tokenize") {
		http.NotFound(w, r)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+h.key)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	attempt := r.Header.Get("X-Hypermesh-Token-Attempt")
	var request struct {
		Model  string
		Stream bool
	}
	body, err := bounded(r.Body)
	if err != nil || json.Unmarshal(body, &request) != nil || request.Stream || request.Model != h.model {
		http.Error(w, "requires a reserved non-streaming request for the bound model", 400)
		return
	}
	if r.URL.Path == "/tokenize" {
		if h.tokenizer == "llama.cpp" {
			h.llamaCount(w, r, body)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), "POST", h.runtime+"/tokenize", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "invalid runtime", 503)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := h.client.Do(req)
		if err != nil {
			http.Error(w, "tokenizer unavailable", 502)
			return
		}
		defer resp.Body.Close()
		result, err := bounded(resp.Body)
		if err != nil || resp.StatusCode != 200 {
			http.Error(w, "tokenizer failed", 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(result)
		return
	}
	if !uuid.MatchString(attempt) {
		http.Error(w, "missing reservation attempt", 400)
		return
	}
	credential, err := os.ReadFile(h.credentialFile)
	if err != nil || strings.TrimSpace(string(credential)) == "" {
		http.Error(w, "device credential unavailable", 503)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), "POST", h.runtime+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "runtime unavailable", 503)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := h.client.Do(req)
	if err != nil {
		http.Error(w, "runtime unavailable", 502)
		return
	}
	defer res.Body.Close()
	data, err := bounded(res.Body)
	var completion struct {
		ID, Model string
		Usage     struct {
			Input  *int `json:"prompt_tokens"`
			Output *int `json:"completion_tokens"`
		}
	}
	if res.StatusCode != 200 || err != nil || json.Unmarshal(data, &completion) != nil || completion.Model != h.model || completion.ID == "" || completion.Usage.Input == nil || completion.Usage.Output == nil || *completion.Usage.Input < 0 || *completion.Usage.Output < 0 {
		http.Error(w, "runtime final usage unavailable", 502)
		return
	}
	receipt, _ := json.Marshal(map[string]any{"model": completion.Model, "recipe": h.recipe, "execution_id": completion.ID, "input_tokens": *completion.Usage.Input, "output_tokens": *completion.Usage.Output})
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	report, err := http.NewRequestWithContext(ctx, "PUT", h.plane+"/api/v1/hypermesh/leases/"+h.lease+"/token-attempts/"+attempt+"/receipt", bytes.NewReader(receipt))
	if err != nil {
		http.Error(w, "receipt unavailable", 503)
		return
	}
	report.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(credential)))
	report.Header.Set("X-Tenant-ID", h.tenant)
	report.Header.Set("Content-Type", "application/json")
	ack, err := h.client.Do(report)
	if err != nil {
		http.Error(w, "receipt unconfirmed", 502)
		return
	}
	defer ack.Body.Close()
	if ack.StatusCode != 200 {
		http.Error(w, "receipt rejected", 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
func validOrigin(raw string, local bool) bool {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if local {
		return u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback()
	}
	return u.Scheme == "https"
}
func run() error {
	env := os.Getenv
	h := host{tokenizer: env("RECEIPT_TOKENIZER"), plane: env("RECEIPT_PLANE_ORIGIN"), runtime: env("RECEIPT_RUNTIME_ORIGIN"), tenant: env("RECEIPT_TENANT"), lease: env("RECEIPT_LEASE"), model: env("RECEIPT_MODEL"), recipe: env("RECEIPT_RECIPE_SHA256"), key: env("RECEIPT_INGRESS_TOKEN"), credentialFile: env("RECEIPT_DEVICE_TOKEN_FILE"), client: &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if (h.tokenizer != "" && h.tokenizer != "llama.cpp") || !validOrigin(h.runtime, true) || !validOrigin(h.plane, false) || !uuid.MatchString(h.lease) || !uuid.MatchString(h.tenant) || !digest.MatchString(h.recipe) || h.model == "" || h.key == "" || h.credentialFile == "" {
		return fmt.Errorf("invalid host receipt configuration")
	}
	server := http.Server{Addr: "127.0.0.1:18081", Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	return server.ListenAndServe()
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
