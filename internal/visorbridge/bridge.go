// Package visorbridge exposes narrowly scoped machine review, never private keys
// or arbitrary command execution, to one configured local Visor account.
package visorbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sync"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
)

var refused = errors.New("host capability bridge refused")

type Binding struct {
	Scope    string `json:"scope"`
	Owner    string `json:"owner"`
	ID       string `json:"capability_id"`
	Revision string `json:"revision"`
	Source   string `json:"source_sha256"`
	Graph    string `json:"graph_sha256"`
}

type Call struct {
	Binding
	CallID    string `json:"call_id"`
	Arguments string `json:"arguments_json"`
}

type Config struct {
	Schema       int       `json:"schema"`
	ClientUID    uint32    `json:"client_uid"`
	Socket       string    `json:"socket"`
	Conductor    string    `json:"conductor"`
	AuthorityURL string    `json:"authority_url"`
	Base         string    `json:"base"`
	Tenant       string    `json:"tenant"`
	Device       string    `json:"device"`
	Identity     string    `json:"identity"`
	WireGuardKey string    `json:"wireguard_key,omitempty"`
	Enabled      []Binding `json:"enabled"`
}

type Result struct {
	Protocol   int    `json:"protocol_version"`
	CallID     string `json:"call_id"`
	CallSHA256 string `json:"call_sha256"`
	Decision   string `json:"decision"`
	Expires    int64  `json:"expires_at"`
}

type signer func(context.Context, machineidentity.CapabilityCall) ([]byte, error)
type reviewer func(context.Context, []byte) ([]byte, error)

type Bridge struct {
	config Config
	sign   signer
	review reviewer
	now    func() time.Time
	busy   chan struct{}
}

func New(config Config) (*Bridge, error) {
	target, err := url.Parse(config.AuthorityURL)
	if err != nil || config.Schema != 1 || config.ClientUID == 0 || len(config.Enabled) > 64 || target.Scheme != "https" || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || target.Path != "/api/v1/aiuditor/capabilities/review" {
		return nil, refused
	}
	if trustedExecutable(config.Conductor) != nil {
		return nil, refused
	}
	seen := map[Binding]bool{}
	for _, binding := range config.Enabled {
		if binding.Scope == "" || binding.Owner == "" || binding.ID == "" || binding.Revision == "" || len(binding.Source) != 64 || len(binding.Graph) != 64 || seen[binding] {
			return nil, refused
		}
		seen[binding] = true
	}
	config.Enabled = append([]Binding(nil), config.Enabled...)
	provider := machineidentity.Provider{Path: config.Identity}
	b := &Bridge{config: config, now: time.Now, busy: make(chan struct{}, 8)}
	b.sign = func(ctx context.Context, call machineidentity.CapabilityCall) ([]byte, error) {
		return provider.SignCapability(ctx, config.Base, config.Tenant, config.Device, config.WireGuardKey, call)
	}
	b.review = func(ctx context.Context, raw []byte) ([]byte, error) {
		if trustedExecutable(config.Conductor) != nil {
			return nil, refused
		}
		cmd := exec.CommandContext(ctx, config.Conductor, "capability-review", "--endpoint", config.AuthorityURL)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}
		cmd.Stdin = bytes.NewReader(raw)
		output := &boundedOutput{limit: 4096}
		cmd.Stdout = output
		cmd.Stderr = io.Discard
		cmd.WaitDelay = time.Second
		if cmd.Run() != nil || output.failed {
			return nil, refused
		}
		return output.buf.Bytes(), nil
	}
	return b, nil
}

type boundedOutput struct {
	buf    bytes.Buffer
	limit  int
	failed bool
	mu     sync.Mutex
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(raw) > b.limit-b.buf.Len() {
		b.failed = true
		return 0, refused
	}
	return b.buf.Write(raw)
}

func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return refused
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return refused
	}
	return nil
}

func (b *Bridge) Review(ctx context.Context, raw []byte) (Result, error) {
	if len(raw) > 140000 {
		return Result{}, refused
	}
	var call Call
	if decode(raw, &call) != nil || len(call.Arguments) > 65536 {
		return Result{}, refused
	}
	allowed := false
	for _, binding := range b.config.Enabled {
		if binding == call.Binding {
			allowed = true
			break
		}
	}
	if !allowed {
		return Result{}, refused
	}
	select {
	case b.busy <- struct{}{}:
		defer func() { <-b.busy }()
	default:
		return Result{}, refused
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	signed, err := b.sign(ctx, machineidentity.CapabilityCall{Scope: call.Scope, Owner: call.Owner, ID: call.ID, Revision: call.Revision, SourceSHA256: call.Source, GraphSHA256: call.Graph, CallID: call.CallID, Arguments: json.RawMessage(call.Arguments)})
	if err != nil {
		return Result{}, refused
	}
	// Check the response against the actual machine proof, not a caller's claim.
	var proof map[string]json.RawMessage
	if json.Unmarshal(signed, &proof) != nil {
		return Result{}, refused
	}
	delete(proof, "signature")
	canonical, err := json.Marshal(proof)
	if err != nil {
		return Result{}, refused
	}
	sum := sha256.Sum256(append([]byte("hypermesh-capability-review-v1\n"), canonical...))
	var expires int64
	if json.Unmarshal(proof["expires_at"], &expires) != nil {
		return Result{}, refused
	}
	result, err := b.review(ctx, signed)
	if err != nil {
		return Result{}, refused
	}
	var verdict struct {
		Protocol int    `json:"protocol_version"`
		CallID   string `json:"call_id"`
		Hash     string `json:"request_sha256"`
		Decision string `json:"decision"`
		Expires  int64  `json:"expires_at"`
	}
	if decode(result, &verdict) != nil || verdict.Protocol != 1 || verdict.CallID != call.CallID || verdict.Hash != hex.EncodeToString(sum[:]) || verdict.Decision != "allow" || verdict.Expires != expires || expires <= b.now().Unix() || expires > b.now().Unix()+30 {
		return Result{}, refused
	}
	bodyHash := sha256.Sum256(raw)
	return Result{1, call.CallID, hex.EncodeToString(bodyHash[:]), "allow", expires}, nil
}

func (b *Bridge) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok || uid != b.config.ClientUID {
			http.Error(w, "host capability bridge refused", 403)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/capabilities" {
			json.NewEncoder(w).Encode(struct {
				Schema  int       `json:"schema"`
				Enabled []Binding `json:"enabled"`
			}{1, b.config.Enabled})
			return
		}
		if r.Method != "POST" || r.URL.Path != "/review" {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 140000))
		if err != nil {
			http.Error(w, "host capability bridge refused", 413)
			return
		}
		result, err := b.Review(r.Context(), raw)
		if err != nil {
			http.Error(w, "host capability bridge refused", 403)
			return
		}
		json.NewEncoder(w).Encode(result)
	})
}

type peerKey struct{}
