//go:build linux || darwin

package machineidentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/FyberLabs/hypermesh-host/internal/tunnel"
)

var errCapability = errors.New("machine capability signing refused")
var capabilityUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var capabilityHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var capabilityName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
var capabilityScope = regexp.MustCompile(`^org/[A-Za-z0-9_-]+/site/[A-Za-z0-9_-]+$`)
var capabilityAuthority = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func validCapability(call CapabilityCall) bool {
	if len(call.Scope) > 270 || !capabilityScope.MatchString(call.Scope) || !capabilityUUID.MatchString(call.CallID) || !capabilityHash.MatchString(call.SourceSHA256) || !capabilityHash.MatchString(call.GraphSHA256) {
		return false
	}
	for _, value := range []string{call.Owner, call.ID, call.Revision} {
		if !capabilityName.MatchString(value) || strings.Contains(value, "..") || strings.Contains(value, "//") || strings.HasSuffix(value, "/") {
			return false
		}
	}
	arguments := bytes.TrimSpace(call.Arguments)
	return len(arguments) > 1 && len(call.Arguments) <= 65536 && arguments[0] == '{' && utf8.Valid(call.Arguments) && json.Valid(call.Arguments)
}

// trustedCapabilityFile never creates, replaces, or changes key-file modes.
func trustedCapabilityFile(path string) (*os.File, error) {
	path = identityPath(path)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errCapability
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		st, err := os.Lstat(dir)
		if err != nil {
			return nil, errCapability
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (st.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && st.Mode()&os.ModeSticky != 0)) {
			return nil, errCapability
		}
		if dir == "/" {
			break
		}
	}
	file, err := safeFile(path)
	if err != nil {
		return nil, errCapability
	}
	return file, nil
}

// SignCapability reads only an existing bound enrollment and WireGuard key.
// The caller supplies its active enrollment context. No key, token, registration
// or owner policy is created, renewed, rotated or weakened by this method.
func (p Provider) SignCapability(ctx context.Context, base, tenant, device, wireguardKeyPath string, call CapabilityCall) ([]byte, error) {
	if !validCapability(call) || !capabilityUUID.MatchString(tenant) || !capabilityUUID.MatchString(device) {
		return nil, errCapability
	}
	var err error
	base, err = identityBase(base)
	if err != nil {
		return nil, errCapability
	}
	if p.Path == "" {
		p.Path = DefaultPath
	}
	p.Path = identityPath(p.Path)
	unlock, err := lock(ctx, p.Path)
	if err != nil {
		return nil, errCapability
	}
	defer unlock()
	s, err := read(p.Path)
	if err != nil || s.Schema != 1 || !s.Bound || s.Pending != "" || s.Base != base || s.Tenant != tenant || s.Device != device || !capabilityUUID.MatchString(s.Request) || !capabilityAuthority.MatchString(s.Authority) || !capabilityAuthority.MatchString(s.Plane) || (p.Authority != "" && p.Authority != s.Authority) {
		return nil, errCapability
	}
	key, err := private(s.Key)
	if err != nil {
		return nil, errCapability
	}
	file, err := trustedCapabilityFile(wireguardKeyPath)
	if err != nil {
		return nil, errCapability
	}
	raw, err := io.ReadAll(io.LimitReader(file, 129))
	file.Close()
	if err != nil || len(raw) > 128 {
		return nil, errCapability
	}
	wireguardPublic, err := tunnel.PublicFromPrivate(string(raw))
	if err != nil {
		return nil, errCapability
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return nil, errCapability
	}
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	arguments := sha256.Sum256(call.Arguments)
	body := map[string]any{
		"protocol_version": 1, "authority_id": s.Authority, "control_plane_id": s.Plane,
		"tenant_id": s.Tenant, "device_id": s.Device, "request_id": s.Request,
		"wireguard_public_key": wireguardPublic, "public_key": public(s.Key),
		"scope": call.Scope, "owner": call.Owner, "capability_id": call.ID, "revision": call.Revision,
		"source_sha256": call.SourceSHA256, "graph_sha256": call.GraphSHA256,
		"arguments_sha256": hex.EncodeToString(arguments[:]), "call_id": call.CallID,
		"issued_at": now.Unix(), "expires_at": now.Unix() + 20, "nonce": hex.EncodeToString(nonce),
	}
	message, err := json.Marshal(body)
	if err != nil {
		return nil, errCapability
	}
	body["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("hypermesh-capability-review-v1\n"), message...)))
	if ctx.Err() != nil {
		return nil, errCapability
	}
	return json.Marshal(body)
}
