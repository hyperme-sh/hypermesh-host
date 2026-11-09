package hostregistration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"time"
)

const NativeMetalProtocol = "metal-llama-bench-depth-v1"

type NativeManifest struct {
	InventoryEpoch     string   `json:"inventory_epoch"`
	SuiteID            string   `json:"suite_id"`
	CatalogID          string   `json:"catalog_id"`
	ClassID            string   `json:"class_id"`
	Purpose            string   `json:"purpose"`
	Protocol           string   `json:"measurement_protocol"`
	FileHash           string   `json:"file_hash"`
	SourceRef          string   `json:"source_ref"`
	SizeBytes          int64    `json:"size_bytes"`
	RuntimeSHA256      string   `json:"runtime_sha256"`
	CollectorCommit    string   `json:"collector_commit"`
	Device             string   `json:"device"`
	EnvironmentHash    string   `json:"environment_hash"`
	Hardware           string   `json:"hardware_fingerprint"`
	OS                 string   `json:"os"`
	Arch               string   `json:"arch"`
	Samples            int      `json:"samples"`
	GeneratedTokens    int      `json:"generated_tokens"`
	ContextTokens      int      `json:"context_tokens"`
	DecodeTokS         float64  `json:"decode_tok_s"`
	ThermalC           *float64 `json:"thermal_c"`
	PhysicalAcceptance bool     `json:"physical_acceptance"`
}

func (m NativeManifest) Validate() error {
	if stamp, e := time.Parse(time.RFC3339Nano, m.InventoryEpoch); e != nil || stamp.IsZero() {
		return fmt.Errorf("native inventory epoch is missing")
	}
	if m.ClassID != "darwin-arm64-lab" || m.Purpose != "native-certification-v1" || m.Protocol != NativeMetalProtocol || m.OS != "darwin" || m.Arch != "arm64" || m.Samples != 3 || m.GeneratedTokens != 32 || m.Device != "MTL0" || m.PhysicalAcceptance || m.ThermalC != nil || !oneOf(m.SuiteID, "pack-v1", "thin-v1") || m.CatalogID == "" || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(m.FileHash) || !hashRE.MatchString(m.RuntimeSHA256) || !hashRE.MatchString(m.Hardware) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(m.CollectorCommit) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(m.EnvironmentHash) || m.ContextTokens < 512 || m.ContextTokens > 131072 || m.SizeBytes <= 0 || m.SizeBytes > 512<<30 || m.DecodeTokS <= 0 || math.IsNaN(m.DecodeTokS) || math.IsInf(m.DecodeTokS, 0) {
		return fmt.Errorf("unsupported or incomplete native certificate manifest")
	}
	return nil
}

type NativeRun struct {
	ProtocolVersion int            `json:"protocol_version"`
	Nonce           string         `json:"nonce"`
	RunID           string         `json:"run_id"`
	TenantID        string         `json:"tenant_id"`
	DeviceID        string         `json:"device_id"`
	RequestID       string         `json:"request_id"`
	Manifest        NativeManifest `json:"manifest"`
	ManifestSHA256  string         `json:"manifest_sha256"`
	State           string         `json:"state"`
	ExpiresAt       time.Time      `json:"expires_at"`
	SellingAllowed  *bool          `json:"selling_allowed"`
}
type NativeSample struct {
	CapturedAt      time.Time `json:"captured_at"`
	ElapsedMS       int64     `json:"elapsed_ms"`
	AverageNS       float64   `json:"average_ns"`
	PromptTokens    int       `json:"prompt_tokens"`
	DepthTokens     int       `json:"depth_tokens"`
	GeneratedTokens int       `json:"generated_tokens"`
	GPULayers       int       `json:"gpu_layers"`
	Device          string    `json:"device"`
	Backend         string    `json:"backend"`
}
type NativeEvidence struct {
	EnvironmentHash    string         `json:"environment_hash"`
	Hardware           string         `json:"hardware_fingerprint"`
	FileHash           string         `json:"file_hash"`
	RuntimeSHA256      string         `json:"runtime_sha256"`
	CollectorCommit    string         `json:"collector_commit"`
	OS                 string         `json:"os"`
	Arch               string         `json:"arch"`
	StartedAt          time.Time      `json:"started_at"`
	CompletedAt        time.Time      `json:"completed_at"`
	Samples            []NativeSample `json:"samples"`
	CleanupComplete    bool           `json:"cleanup_complete"`
	PhysicalAcceptance bool           `json:"physical_acceptance"`
}

func (c *Client) nativeCertification(ctx context.Context, r Request, device, secret, id, environment, hardware string, previous *NativeRun, evidence *NativeEvidence) (NativeRun, error) {
	var out NativeRun
	if r.Validate() != nil || r.ClassID != "darwin-arm64-lab" || !UUID.MatchString(device) || !UUID.MatchString(id) || !onboardingSecretRE.MatchString(secret) {
		return out, fmt.Errorf("invalid native certification identity")
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return out, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	body := map[string]any{"protocol_version": 1, "request_id": r.RequestID, "device_id": device, "run_id": id, "nonce": nonce}
	op := "plan"
	if previous == nil {
		body["environment_hash"] = environment
		body["hardware_fingerprint"] = hardware
	} else {
		op = "result"
		body["manifest_sha256"] = previous.ManifestSHA256
		body["evidence"] = evidence
	}
	if err := c.request(ctx, "POST", "/api/v1/hypermesh/agent/onboarding/native-certification/"+op, secret, body, &out); err != nil {
		return out, err
	}
	if out.ProtocolVersion != 1 || out.Nonce != nonce || out.RunID != id || out.TenantID != c.tenant || out.DeviceID != device || out.RequestID != r.RequestID || out.Manifest.Validate() != nil || !hashRE.MatchString(out.ManifestSHA256) || out.SellingAllowed == nil || *out.SellingAllowed || !oneOf(out.State, "planned", "passed", "failed") || out.ExpiresAt.IsZero() {
		return NativeRun{}, fmt.Errorf("native certification response differs from this installation")
	}
	if previous == nil && (out.Manifest.EnvironmentHash != environment || out.Manifest.Hardware != hardware || out.State != "planned" || !out.ExpiresAt.After(time.Now()) || out.ExpiresAt.After(time.Now().Add(2*time.Hour))) {
		return NativeRun{}, fmt.Errorf("native certification plan differs from measured inventory")
	}
	if previous != nil && (out.ManifestSHA256 != previous.ManifestSHA256 || out.Manifest != previous.Manifest) {
		return NativeRun{}, fmt.Errorf("native certification workload changed")
	}
	return out, nil
}
func (c *Client) PlanNativeCertification(ctx context.Context, r Request, device, secret, id, environment, hardware string) (NativeRun, error) {
	return c.nativeCertification(ctx, r, device, secret, id, environment, hardware, nil, nil)
}
func (c *Client) ReportNativeCertification(ctx context.Context, r Request, device, secret string, run NativeRun, e NativeEvidence) (NativeRun, error) {
	return c.nativeCertification(ctx, r, device, secret, run.RunID, "", "", &run, &e)
}
