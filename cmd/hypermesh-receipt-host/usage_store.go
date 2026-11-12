package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type storedUsage struct {
	Scope string          `json:"scope"`
	State string          `json:"state"`
	Final json.RawMessage `json:"final,omitempty"`
}

func (h host) scope() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{h.plane, h.tenant, h.lease, h.model, h.recipe, h.modelRevision}, "\x00")))
	return hex.EncodeToString(sum[:])
}
func (h host) prepareUsageStore() error {
	if h.usageDir == "" {
		return nil
	}
	if !filepath.IsAbs(h.usageDir) {
		return errors.New("usage outbox must be absolute")
	}
	if err := os.MkdirAll(h.usageDir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(h.usageDir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("usage outbox must be a private directory")
	}
	return nil
}
func (h host) usagePath(attempt string) string { return filepath.Join(h.usageDir, attempt+".json") }
func (h host) beginAttempt(attempt string) error {
	if h.usageDir == "" {
		return nil
	}
	if !uuid.MatchString(attempt) {
		return errors.New("invalid attempt")
	}
	f, err := os.OpenFile(h.usagePath(attempt), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = json.NewEncoder(f).Encode(storedUsage{Scope: h.scope(), State: "uncertain"}); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(h.usageDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (h host) readUsage(attempt string) (storedUsage, error) {
	var item storedUsage
	st, err := os.Lstat(h.usagePath(attempt))
	if err != nil {
		return item, err
	}
	if !st.Mode().IsRegular() || st.Size() > 65536 {
		return item, errors.New("invalid usage entry")
	}
	raw, err := os.ReadFile(h.usagePath(attempt))
	if err != nil {
		return item, err
	}
	if err = json.Unmarshal(raw, &item); err != nil {
		return item, err
	}
	if item.Scope != h.scope() {
		return item, errors.New("usage scope mismatch")
	}
	return item, nil
}
func (h host) storeUsage(attempt string, item storedUsage) error {
	f, err := os.CreateTemp(h.usageDir, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = json.NewEncoder(f).Encode(item); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, h.usagePath(attempt)); err != nil {
		return err
	}
	dir, err := os.Open(h.usageDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (h host) stageUsage(attempt string, raw []byte) error {
	if h.usageDir == "" {
		return nil
	}
	item, err := h.readUsage(attempt)
	if err != nil {
		return err
	}
	if item.State != "uncertain" {
		return errors.New("attempt already finalized")
	}
	item.State = "pending"
	item.Final = raw
	return h.storeUsage(attempt, item)
}
func (h host) finishAttempt(attempt string) error {
	if h.usageDir == "" {
		return nil
	}
	item, err := h.readUsage(attempt)
	if err != nil {
		return err
	}
	if item.State != "pending" {
		return errors.New("attempt is not pending")
	}
	item.State = "final"
	return h.storeUsage(attempt, item)
}
func (h host) replayUsage(ctx context.Context) error {
	if h.usageDir == "" {
		return nil
	}
	entries, err := os.ReadDir(h.usageDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		attempt := strings.TrimSuffix(entry.Name(), ".json")
		if !uuid.MatchString(attempt) {
			return errors.New("invalid stored attempt")
		}
		item, err := h.readUsage(attempt)
		if err != nil {
			return err
		}
		if item.State == "uncertain" || item.State == "final" {
			continue
		}
		if item.State != "pending" || len(item.Final) == 0 {
			return errors.New("invalid pending usage")
		}
		token, err := os.ReadFile(h.credentialFile)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(token)) == "" {
			return errors.New("device credential unavailable")
		}
		boundedCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(boundedCtx, "PUT", h.plane+"/api/v1/hypermesh/leases/"+h.lease+"/token-attempts/"+attempt+"/"+"receipt", bytes.NewReader(item.Final))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		req.Header.Set("X-Tenant-ID", h.tenant)
		req.Header.Set("Content-Type", "application/json")
		resp, err := h.client.Do(req)
		cancel()
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("usage replay rejected: %d", resp.StatusCode)
		}
		if err = h.finishAttempt(attempt); err != nil {
			return err
		}
	}
	return nil
}
