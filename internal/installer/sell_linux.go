//go:build linux

package installer

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const sellUsage = "usage: hypermesh-host sell pause [--until=RFC3339] [--inactive --agent-plan=FILE] | sell resume | sell status"

// RunSell controls selling through the local owner socket. An explicit inactive
// pause records owner intent before a registered first installation starts.
func RunSell(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(diagnostic, "requires root: sudo hypermesh-host sell ...")
		return 1
	}
	return runSell(ctx, "/var/lib/hypermesh", args, out, diagnostic)
}

func runSell(ctx context.Context, stateDir string, args []string, out, diagnostic io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(diagnostic, sellUsage)
		return 2
	}
	method, endpoint := "POST", ""
	var body any
	switch args[0] {
	case "pause":
		f := flag.NewFlagSet("sell pause", flag.ContinueOnError)
		f.SetOutput(diagnostic)
		until := f.String("until", "", "optional RFC3339 time when selling resumes on its own")
		inactive := f.Bool("inactive", false, "record an indefinite owner pause before first service startup")
		agentPlan := f.String("agent-plan", "", "registered inactive installation plan (with --inactive)")
		if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
			fmt.Fprintln(diagnostic, sellUsage)
			return 2
		}
		if *inactive {
			if *agentPlan == "" || *until != "" {
				fmt.Fprintln(diagnostic, "inactive pause requires --agent-plan FILE and no --until")
				return 2
			}
			if err := prepareInactiveOwnerPause(ctx, stateDir, *agentPlan); err != nil {
				fmt.Fprintln(diagnostic, err)
				return 1
			}
			if json.NewEncoder(out).Encode(map[string]any{"sell_state": "paused", "pause_source": "owner", "local_only": true, "agent_started": false}) != nil {
				return 1
			}
			return 0
		}
		if *agentPlan != "" {
			fmt.Fprintln(diagnostic, "--agent-plan requires --inactive")
			return 2
		}
		u := strings.TrimSpace(*until)
		if u != "" {
			if _, err := time.Parse(time.RFC3339, u); err != nil {
				fmt.Fprintln(diagnostic, "--until must be an RFC3339 time such as 2026-10-08T09:00:00Z")
				return 2
			}
		}
		endpoint, body = "/v0/sell_pause", map[string]string{"until": u}
	case "resume":
		if len(args) != 1 {
			fmt.Fprintln(diagnostic, sellUsage)
			return 2
		}
		endpoint, body = "/v0/sell_resume", map[string]string{}
	case "status":
		if len(args) != 1 {
			fmt.Fprintln(diagnostic, sellUsage)
			return 2
		}
		method, endpoint = "GET", "/v0/status"
	default:
		fmt.Fprintln(diagnostic, sellUsage)
		return 2
	}
	var reply struct {
		Passed      *bool  `json:"passed"`
		SellState   string `json:"sell_state"`
		Until       string `json:"until,omitempty"`
		PauseSource string `json:"pause_source,omitempty"`
		Maintenance bool   `json:"maintenance,omitempty"`
		Reason      string `json:"reason,omitempty"`
	}
	if err := ownerSocketRequest(ctx, stateDir, method, endpoint, body, &reply); err != nil {
		fmt.Fprintln(diagnostic, "the host agent did not confirm the request:", err)
		fmt.Fprintln(diagnostic, "Check that hypermesh-agent is running: systemctl status hypermesh-agent")
		return 1
	}
	if json.NewEncoder(out).Encode(reply) != nil {
		return 1
	}
	if reply.Passed != nil && !*reply.Passed {
		switch reply.Reason {
		case "host maintenance hold":
			fmt.Fprintln(diagnostic, "Selling stays paused during maintenance. It resumes when resume-agent completes unless you paused it.")
		case "":
			fmt.Fprintln(diagnostic, "the host agent refused the request")
		default:
			fmt.Fprintln(diagnostic, "the host agent refused the request:", reply.Reason)
		}
		return 1
	}
	return 0
}
