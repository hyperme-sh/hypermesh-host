//go:build !linux

package visorbridge

import "context"

func trustedExecutable(string) error        { return refused }
func Load(string) (Config, error)           { return Config{}, refused }
func (*Bridge) Serve(context.Context) error { return refused }
