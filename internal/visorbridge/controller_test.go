package visorbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func clockFixture(t *testing.T) (*ClockController, Prepare) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux controller")
	}
	directory := t.TempDir()
	os.Chmod(directory, 0700)
	binding := Binding{"org/example/site/lab", "owner", "verb/read-clock", "r1", strings.Repeat("a", 64), strings.Repeat("b", 64)}
	controller, err := NewClockController(ControllerConfig{Schema: 1, StateDir: directory, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	request := Prepare{Call{binding, "11111111-1111-4111-8111-111111111111", `{}`}, Requirements{[]string{"clock-available"}, []Limit{{"controller/read-only", clockRevision}}, []string{"host/clock"}, 1000, 1000}}
	return controller, request
}
func execution(request Prepare, r Reservation) Execute {
	return Execute{request.Call, r.CallHash, r.Permit, r.ObservedMS + 900}
}
func TestClockControllerOwnsRulesAndConsumesCallAcrossRestart(t *testing.T) {
	controller, request := clockFixture(t)
	reservation, err := controller.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(request.Call)
	sum := sha256.Sum256(raw)
	if reservation.CallHash != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong call hash")
	}
	result, err := controller.execute(context.Background(), execution(request, reservation))
	if err != nil || !result.Completed {
		t.Fatal(result, err)
	}
	var output map[string]string
	if json.Unmarshal([]byte(result.Output), &output) != nil || output["unix_nanos"] == "" || output["utc"] == "" {
		t.Fatal("clock output missing")
	}
	if _, err = controller.execute(context.Background(), execution(request, reservation)); err == nil {
		t.Fatal("permit replayed")
	}
	restarted, err := NewClockController(controller.config)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.execute(context.Background(), execution(request, again)); err == nil {
		t.Fatal("call replayed after restart")
	}
}
func TestClockControllerRefusesLoosenedRulesAndMutatingInputs(t *testing.T) {
	for _, mode := range []string{"limit", "condition", "lock", "timeout", "freshness", "argument", "binding"} {
		t.Run(mode, func(t *testing.T) {
			controller, request := clockFixture(t)
			switch mode {
			case "limit":
				request.Requirements.Limits[0].Revision = strings.Repeat("0", 64)
			case "condition":
				request.Requirements.Conditions = nil
			case "lock":
				request.Requirements.Locks = nil
			case "timeout":
				request.Requirements.TimeoutMS = 1001
			case "freshness":
				request.Requirements.FreshnessMS = 1001
			case "argument":
				request.Call.Arguments = `{"set_clock":1}`
			case "binding":
				request.Call.ID = "verb/write-clock"
			}
			if _, err := controller.prepare(request); err == nil {
				t.Fatal("controller rules weakened")
			}
		})
	}
}
func TestClockControllerLocksExpiryAndCancellation(t *testing.T) {
	controller, request := clockFixture(t)
	now := time.Now()
	controller.now = func() time.Time { return now }
	first, err := controller.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.prepare(request); err == nil {
		t.Fatal("lock acquired twice")
	}
	controller.cancel(request.Call.CallID, "wrong")
	if _, err = controller.prepare(request); err == nil {
		t.Fatal("wrong permit unlocked")
	}
	now = now.Add(2 * time.Second)
	if _, err = controller.execute(context.Background(), execution(request, first)); err == nil {
		t.Fatal("stale execution")
	}
	controller.cancel(request.Call.CallID, first.Permit)
	second, err := controller.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if _, err = controller.execute(context.Background(), execution(request, second)); err == nil {
		t.Fatal("expired permit executed")
	}
	if _, err = controller.prepare(request); err != nil {
		t.Fatal("expired lock retained", err)
	}
}
func TestControllerRejectsNonRootPeerBeforeBody(t *testing.T) {
	controller, _ := clockFixture(t)
	request := httptest.NewRequest("POST", "/execute", strings.NewReader("private untrusted body"))
	request = request.WithContext(context.WithValue(request.Context(), peerKey{}, uint32(1001)))
	request.Header.Set("X-UID", "0")
	response := httptest.NewRecorder()
	controller.Handler().ServeHTTP(response, request)
	if response.Code != 403 || strings.Contains(response.Body.String(), "private") {
		t.Fatal("untrusted controller peer")
	}
}
