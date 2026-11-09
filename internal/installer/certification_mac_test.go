//go:build linux || darwin

package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/buildinfo"
	"github.com/FyberLabs/hypermesh-host/internal/certmeasure"
	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
)

func nativeFixtureReport() (certmeasure.Report, hostregistration.NativeManifest) {
	now := time.Now().UTC()
	m := hostregistration.NativeManifest{InventoryEpoch: time.Now().UTC().Format(time.RFC3339Nano), SuiteID: "pack-v1", CatalogID: "mac-model", ClassID: macLabClass, Purpose: "native-certification-v1", Protocol: hostregistration.NativeMetalProtocol, FileHash: "sha256:" + strings.Repeat("a", 64), RuntimeSHA256: strings.Repeat("b", 64), CollectorCommit: strings.Repeat("d", 40), Device: "MTL0", EnvironmentHash: "sha256:" + strings.Repeat("e", 64), Hardware: strings.Repeat("f", 64), OS: "darwin", Arch: "arm64", Samples: 3, GeneratedTokens: 32, ContextTokens: 4096, DecodeTokS: 40, SizeBytes: 3}
	r := certmeasure.Report{Schema: "hypermesh-certification-measurements-v1", CollectorCommit: m.CollectorCommit, Device: m.Device, EnvironmentHash: m.EnvironmentHash, Hardware: m.Hardware, ModelSHA256: strings.TrimPrefix(m.FileHash, "sha256:"), RuntimeSHA256: m.RuntimeSHA256, OS: m.OS, Arch: m.Arch, Backend: "metal", ContextTokens: m.ContextTokens, GeneratedTokens: 32, StartedAt: now, CompletedAt: now.Add(3 * time.Second), MeasurementState: "passed", CertificationState: "not_evaluated"}
	for i := 0; i < 3; i++ {
		raw := json.RawMessage(`[{"avg_ns":800000000,"samples_ns":[800000000],"n_prompt":0,"n_depth":4064,"n_gen":32,"n_gpu_layers":99,"devices":"MTL0","backends":"MTL,BLAS"}]`)
		r.Samples = append(r.Samples, certmeasure.Sample{CapturedAt: now.Add(time.Duration(i) * time.Second), ElapsedMS: 900, TokensPerSecond: 40, Raw: raw})
	}
	return r, m
}
func TestNativeProofRejectsMismatchedRawReports(t *testing.T) {
	for _, mutation := range []string{"ok", "context", "cpu", "missing", "nan", "pins", "hardware", "failed", "raw"} {
		t.Run(mutation, func(t *testing.T) {
			r, m := nativeFixtureReport()
			switch mutation {
			case "context":
				r.ContextTokens = 512
			case "cpu":
				r.Device = "CPU"
			case "missing":
				r.Samples = r.Samples[:2]
			case "nan":
				r.Samples[0].Raw = json.RawMessage(`[{"avg_ns":"NaN"}]`)
			case "pins":
				r.RuntimeSHA256 = strings.Repeat("a", 64)
			case "hardware":
				r.Hardware = strings.Repeat("a", 64)
			case "failed":
				r.MeasurementState = "failed"
			case "raw":
				r.Samples[0].Raw = bytes.ReplaceAll(r.Samples[0].Raw, []byte(`"n_depth":4064`), []byte(`"n_depth":512`))
			}
			e, err := nativeEvidence(r, m)
			if (err == nil) != (mutation == "ok") {
				t.Fatal(err)
			}
			if mutation == "ok" && (len(e.Samples) != 3 || e.Samples[0].DepthTokens != 4064 || !e.CleanupComplete) {
				t.Fatal(e)
			}
		})
	}
}

type fakeNativeRemote struct {
	planCalls, reportCalls int
	run                    hostregistration.NativeRun
	losePlan, loseReport   bool
}

func (f *fakeNativeRemote) PlanNativeCertification(_ context.Context, r hostregistration.Request, device, secret, id, env, hw string) (hostregistration.NativeRun, error) {
	f.planCalls++
	if f.run.RunID != "" && f.run.RunID != id {
		return hostregistration.NativeRun{}, fmt.Errorf("retry changed run")
	}
	_, m := nativeFixtureReport()
	no := false
	f.run = hostregistration.NativeRun{ProtocolVersion: 1, RunID: id, TenantID: macTestTenant, DeviceID: device, RequestID: r.RequestID, Manifest: m, ManifestSHA256: strings.Repeat("c", 64), State: "planned", ExpiresAt: time.Now().Add(time.Hour), SellingAllowed: &no}
	if f.losePlan {
		f.losePlan = false
		return hostregistration.NativeRun{}, fmt.Errorf("lost planning response")
	}
	return f.run, nil
}
func (f *fakeNativeRemote) ReportNativeCertification(_ context.Context, r hostregistration.Request, device, secret string, run hostregistration.NativeRun, e hostregistration.NativeEvidence) (hostregistration.NativeRun, error) {
	f.reportCalls++
	if f.loseReport {
		f.loseReport = false
		return hostregistration.NativeRun{}, fmt.Errorf("lost upload response")
	}
	run.State = "passed"
	return run, nil
}
func TestNativePlanningAndUploadRetriesRetainIdentityAndWork(t *testing.T) {
	f := newMacFixture(t)
	if code, _, diag := f.run(); code != 0 {
		t.Fatal(diag)
	}
	j := f.journal(t)
	old := buildinfo.Commit
	buildinfo.Commit = strings.Repeat("d", 40)
	defer func() { buildinfo.Commit = old }()
	remote := &fakeNativeRemote{losePlan: true, loseReport: true}
	measureCalls := 0
	r, m := nativeFixtureReport()
	d := nativeDeps{registration: f.d, inventory: func(context.Context) (string, string, error) { return m.EnvironmentHash, m.Hardware, nil }, remote: func(string, string) (nativeRemote, error) { return remote, nil }, measure: func(_ context.Context, args []string, out, diag io.Writer) int {
		measureCalls++
		dir := filepath.Join(f.d.root, "artifacts", "run")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(r)
		path := filepath.Join(dir, "report.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(out, path)
		return 0
	}}
	os.Mkdir(filepath.Join(f.d.root, "native"), 0700)
	path := filepath.Join(f.d.root, "native", "plan.json")
	planArgs := []string{"--registration-plan-sha", j.PlanSHA256, "--plan", path}
	call := func(planning bool, args []string) (int, string, string) {
		var out, diag bytes.Buffer
		code := runMacNativeCertification(context.Background(), args, &out, &diag, planning, d)
		return code, out.String(), diag.String()
	}
	if code, _, diag := call(true, planArgs); code == 0 || !strings.Contains(diag, "lost planning response") {
		t.Fatal("unexpected planning response", code, diag)
	}
	raw, _ := os.ReadFile(path)
	var before nativePlan
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	if code, _, diag := call(true, planArgs); code != 0 {
		t.Fatal(diag)
	}
	raw, _ = os.ReadFile(path)
	var p nativePlan
	json.Unmarshal(raw, &p)
	if p.RunID != before.RunID || remote.planCalls != 2 {
		t.Fatal("planning identity changed")
	}
	model := filepath.Join(f.d.root, "model.gguf")
	os.WriteFile(model, []byte("abc"), 0600)
	args := []string{"--plan", path, "--approve-plan", nativePlanDigest(p), "--model-file", model, "--runtime-file", "/unused", "--artifact-dir", filepath.Join(f.d.root, "artifacts"), "--run"}
	if code, _, _ := call(false, args); code == 0 {
		t.Fatal("lost upload accepted")
	}
	if code, _, diag := call(false, args); code != 0 {
		t.Fatal(diag)
	}
	if measureCalls != 1 || remote.reportCalls != 2 {
		t.Fatalf("reran measurements: %d, uploads: %d", measureCalls, remote.reportCalls)
	}
	if code, _, diag := call(false, args); code != 0 {
		t.Fatal(diag)
	}
	f.loaded["com.fyberlabs.hypermesh-agent"] = true
	if code, _, _ := call(false, args); code == 0 {
		t.Fatal("loaded agent permitted")
	}
	if measureCalls != 1 {
		t.Fatal("workload restarted")
	}
	for _, secret := range []string{j.DeviceSecret, j.PrivateKey} {
		receipt, _ := os.ReadFile(path + ".result.json")
		if bytes.Contains(receipt, []byte(secret)) {
			t.Fatal("credential leaked")
		}
	}
}
