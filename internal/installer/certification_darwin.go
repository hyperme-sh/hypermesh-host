//go:build darwin

package installer

import (
	"context"
	"errors"
	"fmt"
	"github.com/FyberLabs/hypermesh-host/internal/hardware"
	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
	"github.com/FyberLabs/hypermesh-host/internal/telem"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/certmeasure"
)

// Local measurements remain available independently of certificate issuance.
func RunCertifyAgent(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	for _, arg := range args {
		if arg == "--plan" || arg == "-plan" || strings.HasPrefix(arg, "--plan=") || strings.HasPrefix(arg, "-plan=") {
			return runNativeMac(ctx, args, out, diagnostic, false)
		}
	}
	return certmeasure.Run(ctx, args, out, diagnostic)
}
func RunPlanCertification(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	return runNativeMac(ctx, args, out, diagnostic, true)
}
func runNativeMac(ctx context.Context, args []string, out, diagnostic io.Writer, planning bool) int {
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		fmt.Fprintln(diagnostic, "native certificate execution requires root on Apple silicon")
		return 1
	}
	if err := os.Setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"); err != nil {
		return 1
	}
	d := nativeDeps{registration: macRegistrationDeps{detect: hardware.Detect, command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root", "LC_ALL=C"}
		return cmd.Output()
	}, absent: func(err error) bool { var e *exec.ExitError; return errors.As(err, &e) && e.ExitCode() == 113 }},
		inventory: func(ctx context.Context) (string, string, error) {
			s, e := telem.Default().Collect(ctx)
			if e != nil {
				return "", "", e
			}
			return s.EnvironmentHash, hardware.Detect(ctx).Fingerprint, nil
		}, remote: func(base, tenant string) (nativeRemote, error) {
			c, e := hostregistration.New(base, tenant)
			if e == nil {
				c.SetMachineIdentity(machineidentity.DefaultPath)
			}
			return c, e
		}, measure: certmeasure.Run}
	return runMacNativeCertification(ctx, args, out, diagnostic, planning, d)
}
func RunActivateAgent(_ context.Context, _ []string, _ io.Writer, diagnostic io.Writer) int {
	fmt.Fprintln(diagnostic, "Native certificates leave the experimental Mac class paused; activation requires its separate supported owner contract")
	return 1
}
