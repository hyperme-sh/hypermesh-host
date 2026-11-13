package visorbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
)

func signCall(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	fs := flag.NewFlagSet("visor sign-call", flag.ContinueOnError)
	fs.SetOutput(diagnostic)
	path := fs.String("call", "", "local capability call JSON file")
	identity := fs.String("identity", machineidentity.DefaultPath, "existing enrolled-machine checkpoint")
	wireguard := fs.String("wireguard-key", "/etc/wireguard/hypermesh.key", "existing private WireGuard key file (read only)")
	base := fs.String("base", "", "active enrollment HTTPS control-plane base")
	tenant := fs.String("tenant", "", "active enrollment tenant UUID")
	device := fs.String("device", "", "active enrollment device UUID")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *path == "" || *base == "" || *tenant == "" || *device == "" {
		fmt.Fprintln(diagnostic, "call, base, tenant and device are required")
		return 2
	}
	file, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(diagnostic, "cannot read capability call")
		return 1
	}
	defer file.Close()
	var call machineidentity.CapabilityCall
	reader := io.LimitReader(file, 70001)
	raw, err := io.ReadAll(reader)
	if err != nil || len(raw) > 70000 {
		fmt.Fprintln(diagnostic, "invalid capability call")
		return 1
	}
	if err = decodeCall(raw, &call); err != nil {
		fmt.Fprintln(diagnostic, "invalid capability call")
		return 1
	}
	signed, err := (machineidentity.Provider{Path: *identity}).SignCapability(ctx, *base, *tenant, *device, *wireguard, call)
	if err != nil {
		fmt.Fprintln(diagnostic, "machine capability signing refused")
		return 1
	}
	if _, err = out.Write(append(signed, '\n')); err != nil {
		return 1
	}
	return 0
}

func decodeCall(raw []byte, call *machineidentity.CapabilityCall) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(call); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid capability call")
	}
	return nil
}
