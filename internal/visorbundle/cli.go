package visorbundle

import (
	"context"
	"flag"
	"fmt"
	"github.com/FyberLabs/hypermesh-host/internal/update"
	"github.com/FyberLabs/hypermesh-host/internal/visorbridge"
	"io"
	"os"
)

func Run(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(diagnostic, "usage: hypermesh-host visor install|remove --directory PATH; visor sign-call --help")
		return 2
	}
	if args[0] == "controller" {
		return visorbridge.RunController(ctx, args[1:], diagnostic)
	}
	if args[0] == "bridge" {
		return visorbridge.Run(ctx, args[1:], diagnostic)
	}
	if args[0] == "sign-call" {
		return signCall(ctx, args[1:], out, diagnostic)
	}
	action := args[0]
	if action != "install" && action != "remove" {
		fmt.Fprintln(diagnostic, "visor action must be install or remove")
		return 2
	}
	fs := flag.NewFlagSet("visor "+action, flag.ContinueOnError)
	fs.SetOutput(diagnostic)
	directory := fs.String("directory", "", "new private bundle directory under an existing owned mode-0700 parent")
	var manifest, keyPath, fingerprints string
	if action == "install" {
		fs.StringVar(&manifest, "manifest", "", "local JSON descriptor containing short-lived artifact URLs")
		fs.StringVar(&keyPath, "trusted-key", "", "independently trusted armored signing public key")
		fs.StringVar(&fingerprints, "fingerprints", "", "independently trusted signing fingerprints")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *directory == "" {
		fmt.Fprintln(diagnostic, "explicit directory and no positional arguments required")
		return 2
	}
	var err error
	if action == "remove" {
		err = Remove(*directory)
	} else {
		fps, e := update.ParseFingerprints(fingerprints)
		if e != nil || len(fps) == 0 || keyPath == "" || manifest == "" {
			fmt.Fprintln(diagnostic, "manifest, trusted key and fingerprints required")
			return 2
		}
		file, e := os.Open(manifest)
		if e != nil {
			fmt.Fprintln(diagnostic, "cannot open manifest")
			return 1
		}
		m, e := Decode(file)
		_ = file.Close()
		if e != nil {
			fmt.Fprintln(diagnostic, e)
			return 1
		}
		file, e = os.Open(keyPath)
		if e != nil {
			fmt.Fprintln(diagnostic, "cannot open trusted key")
			return 1
		}
		key, e := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		_ = file.Close()
		if e != nil || len(key) == 0 || len(key) > 1<<20 {
			fmt.Fprintln(diagnostic, "invalid trusted key size")
			return 1
		}
		err = Install(ctx, m, *directory, key, fps)
	}
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	if action == "install" {
		fmt.Fprintln(out, "Verified headless bundle installed. No service or capability was started.")
	} else {
		fmt.Fprintln(out, "Headless bundle removed.")
	}
	return 0
}
