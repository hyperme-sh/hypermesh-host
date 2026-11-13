package visorbridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// The reference driver can only read the clock. No configuration or request can
// turn it into a shell, actuator, writable file API or programmable controller.
const clockRule = "hypermesh-clock-controller-v1\nread-only\nno-arguments\n"

var clockRevision = fmt.Sprintf("%x", sha256.Sum256([]byte(clockRule)))
var callUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type Limit struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}
type Requirements struct {
	Conditions  []string `json:"conditions"`
	Limits      []Limit  `json:"limits"`
	Locks       []string `json:"locks"`
	TimeoutMS   int      `json:"timeout_ms"`
	FreshnessMS int      `json:"freshness_ms"`
}
type Prepare struct {
	Call         Call         `json:"call"`
	Requirements Requirements `json:"requirements"`
}
type Reservation struct {
	Protocol   int      `json:"protocol_version"`
	CallID     string   `json:"call_id"`
	CallHash   string   `json:"call_sha256"`
	Permit     string   `json:"permit"`
	ObservedMS int64    `json:"observed_at_ms"`
	ExpiresMS  int64    `json:"expires_at_ms"`
	Conditions []string `json:"conditions"`
	Limits     []Limit  `json:"limits"`
	Locks      []string `json:"locks"`
}
type Execute struct {
	Call       Call   `json:"call"`
	CallHash   string `json:"call_sha256"`
	Permit     string `json:"permit"`
	DeadlineMS int64  `json:"deadline_ms"`
}
type Executed struct {
	Protocol  int    `json:"protocol_version"`
	CallID    string `json:"call_id"`
	CallHash  string `json:"call_sha256"`
	Completed bool   `json:"completed"`
	Output    string `json:"output_json"`
}
type ControllerConfig struct {
	Schema   int     `json:"schema"`
	Socket   string  `json:"socket"`
	StateDir string  `json:"state_dir"`
	Binding  Binding `json:"binding"`
}
type ClockController struct {
	config    ControllerConfig
	mu        sync.Mutex
	active    *Reservation
	freshness int
	count     int
	now       func() time.Time
}

func NewClockController(config ControllerConfig) (*ClockController, error) {
	if config.Schema != 1 || controllerStateDir(config.StateDir) != nil {
		return nil, refused
	}
	entries, err := os.Open(config.StateDir)
	if err != nil {
		return nil, refused
	}
	names, err := entries.Readdirnames(100001)
	entries.Close()
	if err != nil && err != io.EOF {
		return nil, refused
	}
	if len(names) > 100000 {
		return nil, refused
	}
	return &ClockController{config: config, count: len(names), now: time.Now}, nil
}
func (c *ClockController) valid(call Call) bool {
	if call.Binding != c.config.Binding || !callUUID.MatchString(call.CallID) || len(call.Arguments) > 65536 {
		return false
	}
	var args map[string]json.RawMessage
	return json.Unmarshal([]byte(call.Arguments), &args) == nil && args != nil && len(args) == 0
}
func (c *ClockController) prepare(request Prepare) (Reservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.active != nil && c.active.ExpiresMS <= now.UnixMilli() {
		c.active = nil
	}
	r := request.Requirements
	if !c.valid(request.Call) || c.active != nil || r.TimeoutMS < 1 || r.TimeoutMS > 1000 || r.FreshnessMS < 1 || r.FreshnessMS > 1000 || len(r.Conditions) != 1 || r.Conditions[0] != "clock-available" || len(r.Locks) != 1 || r.Locks[0] != "host/clock" || len(r.Limits) != 1 || r.Limits[0] != (Limit{"controller/read-only", clockRevision}) {
		return Reservation{}, refused
	}
	raw, _ := json.Marshal(request.Call)
	sum := sha256.Sum256(raw)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return Reservation{}, refused
	}
	reservation := Reservation{1, request.Call.CallID, hex.EncodeToString(sum[:]), hex.EncodeToString(nonce), now.UnixMilli(), now.Add(5 * time.Second).UnixMilli(), []string{"clock-available"}, []Limit{{"controller/read-only", clockRevision}}, []string{"host/clock"}}
	c.active = &reservation
	c.freshness = r.FreshnessMS
	return reservation, nil
}
func (c *ClockController) execute(ctx context.Context, request Execute) (Executed, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	r := c.active
	raw, _ := json.Marshal(request.Call)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	if r == nil || request.Permit != r.Permit || request.Call.CallID != r.CallID || request.CallHash != r.CallHash || hash != r.CallHash || !c.valid(request.Call) || request.DeadlineMS > r.ExpiresMS || now.UnixMilli() >= request.DeadlineMS || now.UnixMilli()-r.ObservedMS > int64(c.freshness) || ctx.Err() != nil {
		return Executed{}, refused
	}
	// Consume before any operation; the durable record also survives a process
	// restart or a lost response. There is no method that deletes these records.
	c.active = nil
	if c.count >= 100000 {
		return Executed{}, refused
	}
	path := filepath.Join(c.config.StateDir, request.Call.CallID)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Executed{}, refused
	}
	c.count++
	_, err = file.WriteString(hash + "\n")
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return Executed{}, refused
	}
	directory, err := os.Open(c.config.StateDir)
	if err != nil {
		return Executed{}, refused
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return Executed{}, refused
	}
	now = c.now()
	if ctx.Err() != nil || now.UnixMilli() >= request.DeadlineMS || now.UnixMilli()-r.ObservedMS > int64(c.freshness) {
		return Executed{}, refused
	}
	output, _ := json.Marshal(map[string]string{"unix_nanos": fmt.Sprint(now.UnixNano()), "utc": now.UTC().Format(time.RFC3339Nano)})
	return Executed{1, request.Call.CallID, hash, true, string(output)}, nil
}
func (c *ClockController) cancel(id, permit string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil && c.active.CallID == id && c.active.Permit == permit {
		c.active = nil
	}
}
func (c *ClockController) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok || uid != 0 {
			http.Error(w, "controller refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 150000))
		if err != nil {
			http.Error(w, "controller refused", 413)
			return
		}
		var result any
		switch r.URL.Path {
		case "/prepare":
			var request Prepare
			if decode(raw, &request) != nil {
				err = refused
			} else {
				result, err = c.prepare(request)
			}
		case "/execute":
			var request Execute
			if decode(raw, &request) != nil {
				err = refused
			} else {
				result, err = c.execute(r.Context(), request)
			}
		case "/cancel":
			var request struct {
				ID     string `json:"call_id"`
				Permit string `json:"permit"`
			}
			if decode(raw, &request) != nil {
				err = refused
			} else {
				c.cancel(request.ID, request.Permit)
				result = map[string]bool{"cancelled": true}
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "controller refused", 403)
			return
		}
		json.NewEncoder(w).Encode(result)
	})
}
func RunController(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	fs := flag.NewFlagSet("visor controller", flag.ContinueOnError)
	fs.SetOutput(diagnostic)
	path := fs.String("config", "", "owned read-only clock controller config")
	describe := fs.Bool("describe", false, "print the immutable driver requirements")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	if *describe {
		if *path != "" {
			return 2
		}
		if err := json.NewEncoder(out).Encode(Requirements{[]string{"clock-available"}, []Limit{{"controller/read-only", clockRevision}}, []string{"host/clock"}, 1000, 1000}); err != nil {
			return 1
		}
		return 0
	}
	if *path == "" || trustedConfiguration(*path) != nil {
		return 2
	}
	file, err := os.Open(*path)
	if err != nil {
		return 1
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	file.Close()
	var config ControllerConfig
	if err != nil || len(raw) > 16384 || decode(raw, &config) != nil {
		fmt.Fprintln(diagnostic, "controller refused")
		return 1
	}
	controller, err := NewClockController(config)
	if err != nil {
		fmt.Fprintln(diagnostic, "controller refused")
		return 1
	}
	if serveSocket(ctx, config.Socket, 0, controller.Handler()) != nil {
		fmt.Fprintln(diagnostic, "controller refused")
		return 1
	}
	return 0
}
