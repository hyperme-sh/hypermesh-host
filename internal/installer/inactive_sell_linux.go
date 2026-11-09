//go:build linux

package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FyberLabs/hypermesh-host/internal/agent"
	"github.com/FyberLabs/hypermesh-host/internal/api"
)

// This only narrows intake before an inactive first installation starts. Online
// pause/resume still use the authenticated owner socket. Never silently fall back
// from a failed owner request to an offline state change.
func prepareInactiveOwnerPause(ctx context.Context, stateDir, planPath string) error {
	if stateDir != "/var/lib/hypermesh" {
		return fmt.Errorf("inactive pause requires the installed host state")
	}
	var p agentInstallPlan
	raw, err := readSetupRegular(planPath, false)
	if err == nil {
		err = decodeSetupJSON(raw, &p)
	}
	if err != nil || validateInstalledAgentInputs(p) != nil || agentPlanDigest(p) != p.SHA256 {
		return fmt.Errorf("valid installed agent plan required")
	}
	unlock, err := lockSetupState(defaultSetupState)
	if err != nil {
		return err
	}
	defer unlock()
	if err = verifyRegistrationService(ctx, p); err != nil {
		return err
	}
	var registration registrationJournal
	raw, err = readSetupRegular(registrationPath(defaultSetupState, p.SHA256), true)
	if err == nil {
		err = decodeSetupJSON(raw, &registration)
	}
	if err != nil || validateRegistration(registration, p, registration.Issuer, registration.Dashboard, registration.Request.ClassID) != nil || registration.State != "registered-inactive" {
		return fmt.Errorf("current inactive registration required")
	}
	if err = checkRegistrationIdentity("", registration, true); err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(stateDir, "lease.json")); !os.IsNotExist(err) {
		return fmt.Errorf("reconcile the existing lease before inactive pause")
	}
	return writeInactiveOwnerPause(filepath.Join(stateDir, "sell.json"))
}

func writeInactiveOwnerPause(path string) error {
	posture := agent.SellPosture{SellState: api.SellPaused, Source: agent.SellSourceOwner}
	data, err := json.Marshal(posture)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(path); err == nil {
		raw, e := readSetupRegular(path, true)
		if e != nil {
			return e
		}
		var current agent.SellPosture
		if decodeSetupJSON(raw, &current) != nil || current.SellState != posture.SellState || current.Source != posture.Source || current.Until != "" {
			return fmt.Errorf("existing sell posture differs; preserve it and use its owning lifecycle")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect inactive selling intent")
	}
	return writeAgentFile(path, agentPayload{agentFile{path, digestSetupBytes(data), 0600}, data})
}
