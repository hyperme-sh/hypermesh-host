//go:build linux

package installer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInactivePauseSurvivesActivationWithoutStartingSelling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sell.json")
	if err := writeInactiveOwnerPause(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keep, err := activationKeepsSell(raw, time.Now())
	if err != nil || !keep {
		t.Fatalf("owner pause lost: %s %v", raw, err)
	}
	if wrote, err := prepareActivationSell(path, time.Now()); err != nil || wrote {
		t.Fatalf("activation replaced owner pause: %v %v", wrote, err)
	}
	if err := writeInactiveOwnerPause(path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("idempotent pause changed bytes")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("pause must remain private")
	}
}

func TestInactivePauseRefusesOtherPosturesAndLinks(t *testing.T) {
	for _, raw := range []string{`{"sell_state":"selling"}`, `{"sell_state":"paused","source":"activation"}`, `{"sell_state":"paused","source":"owner","until":"2099-01-01T00:00:00Z"}`, `{"sell_state":"paused","source":"owner","extra":true}`, `broken`} {
		path := filepath.Join(t.TempDir(), "sell.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if err := writeInactiveOwnerPause(path); err == nil {
			t.Fatalf("accepted conflicting posture: %s", raw)
		}
		after, _ := os.ReadFile(path)
		if string(after) != raw {
			t.Fatal("changed a conflicting posture")
		}
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sell.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeInactiveOwnerPause(path); err == nil {
		t.Fatal("accepted symlink")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "keep" {
		t.Fatal("changed linked target")
	}
}

func TestInactivePauseCLIRefusesUnboundOrTimedRequestsBeforeOwnerSocket(t *testing.T) {
	for _, args := range [][]string{{"pause", "--inactive"}, {"pause", "--inactive", "--agent-plan", "x", "--until", "2099-01-01T00:00:00Z"}, {"pause", "--agent-plan", "x"}} {
		var out, diag bytes.Buffer
		if got := runSell(context.Background(), t.TempDir(), args, &out, &diag); got != 2 {
			t.Fatalf("%v: %d %s", args, got, diag.String())
		}
		if out.Len() != 0 || strings.Contains(diag.String(), "agent did not confirm") {
			t.Fatal("invalid offline arguments reached owner socket")
		}
	}
	if err := prepareInactiveOwnerPause(context.Background(), t.TempDir(), "missing"); err == nil {
		t.Fatal("accepted alternate installation root")
	}
}
