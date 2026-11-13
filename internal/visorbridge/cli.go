package visorbridge

import (
	"context"
	"flag"
	"fmt"
	"io"
)

func Run(ctx context.Context, args []string, out io.Writer) int {
	fs := flag.NewFlagSet("visor bridge", flag.ContinueOnError)
	fs.SetOutput(out)
	path := fs.String("config", "", "owned bridge configuration")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(out, "bridge requires --config")
		return 2
	}
	config, err := Load(*path)
	if err != nil {
		fmt.Fprintln(out, "host capability bridge refused")
		return 1
	}
	bridge, err := New(config)
	if err != nil {
		fmt.Fprintln(out, "host capability bridge refused")
		return 1
	}
	if bridge.Serve(ctx) != nil {
		fmt.Fprintln(out, "host capability bridge refused")
		return 1
	}
	return 0
}
